# camada

camada for PHP: enforces the tenant snapshot inline (your ordered custom rules, then allow,
block, challenge), serves a first-party proof-of-work challenge page and beacon, records the
outcomes your handlers know (`track()`), and ships wire events in batches after the response has
left. One package (`camada/camada`) with a plain front-controller adapter that needs
nothing but `$_SERVER`, `php://input` and `header()` — FPM, `php -S`, mod_php — and a Laravel
middleware. Fails open by design: a camada outage or bug never 5xxes your app.

Not yet on Packagist — install it from a sibling checkout with a path repository, as
[`camada-php-example`](../camada-php-example) does; publishing is one decision with the npm
packages (SDK-G01). PHP 8.1 or newer, `ext-json` and `ext-zlib` (the snapshot travels gzipped),
`ext-openssl` to reach an https analyst (the transport is a small HTTP/1.1 client over a stream
socket, so `allow_url_fopen` is not needed), no runtime dependencies.

```json
{ "repositories": [{ "type": "path", "url": "../camada-php" }], "require": { "camada/camada": "*@dev" } }
```

## Quickstart

```php
<?php
// public/index.php — any front controller
require __DIR__ . '/../vendor/autoload.php';

use Camada\Camada;
use Camada\Http\Sapi;

$cam = Camada::default();      // built lazily from the environment, once per request
$ctx = Sapi::run($cam);        // null: camada answered (block, challenge, beacon) and the script must stop
if ($ctx === null) {
    return;
}
// your app: x-rid and the _sfp cookie are already on the response; $ctx->rid, $ctx->sid, $ctx->ip are yours
```

```php
// Laravel — bootstrap/app.php (11+) or app/Http/Kernel.php: first in the global stack
->withMiddleware(fn (Middleware $m) => $m->prepend(\Camada\Laravel\Middleware::class))
// the context rides $request->attributes->get('camada')
```

Env (printed by camada onboarding / `npm run seed` in dev):

```
CAMADA_KEY=<ingest_token>.<snap_token>
CAMADA_INGEST_URL=http://localhost:8787        # dev only; defaults to production ingest
```

Without `CAMADA_KEY` the engine is inert (one log line, no files, no requests, no enforcement).
An app that reads its own config builds the engine itself and hands it in:

```php
$cam = new Camada(env: ['CAMADA_KEY' => $key, 'CAMADA_INGEST_URL' => $ingest]);
$ctx = Sapi::run($cam);                       // Laravel: Camada::setDefault($cam) in a service provider — the kernel builds the middleware itself
```

## The file-backed runtime

A PHP process lives for one request, so the poll thread and the flush thread the other SDKs
run become one runtime on disk that every worker of every SAPI shares:

```
$CAMADA_CACHE_DIR (default: <system temp dir>/camada-<16 hex of sha256(snap token)>)
  snapshot.bin        the raw BLK container, seeked into per request (never parsed whole)
  snapshot.meta.json  its meta (rules, sides, version)
  state.json          {etag, version, loaded_at, refresh_s, config, none}
  events.ndjson       the spool, one wire event per line       events.lock / events.count / flush.json
  refresh.lock        one refresh in flight across workers      log.stamp: one log line a minute
```

Every write is `tmp + rename()`, so a reader never sees a torn file. On the request path the
engine reads `state.json`, looks the client up in the cached container (a handful of seeks, no
5 MB parse) and decides; it never opens a socket. The snapshot refresh and the event shipping run
in the **post-response phase**, after the client has its bytes: under FPM and FrankenPHP
`fastcgi_finish_request()` ends the response; under `php -S` and mod_php the adapter's output
buffer is flushed with a `Content-Length` so the client can stop reading. Then, in order: the
request's event is appended to the spool; a due spool (≥ 500 rows, or 15 s since the last flush)
is renamed to a private file and POSTed to `/e` in slices of ≤ 1000; a stale snapshot (0.9 × the
poll cadence) is fetched under `refresh.lock`, non-blocking — a busy lock means another worker is
on it.

Consequences worth knowing: the first request after a deploy (or an emptied cache) is answered
cold — it passes (fail open) and arms the refresh; the next request enforces. A request whose
spool is due ships it, so a quiet site ships its last events on its next hit, not on a timer. The
cache dir must be a local, writable directory (`flock()` and `rename()` are the concurrency
model; a network mount is not). Each container or host keeps its own copy.

To enforce from request 1, warm the cache in a deploy step: `refresh()` is synchronous, single
in-flight, and returns at once when another worker holds the lock, so the loop is bounded. The
step must warm the directory the workers read: set `CAMADA_CACHE_DIR` explicitly for both (the
default lives under the system temp dir, which is per-service under systemd's `PrivateTmp`, and
is created `0700`), and run it as the FPM pool's user.

```php
$cam = Camada::default();
if ($cam->snap !== null) {                    // null when CAMADA_KEY is unset or CAMADA_DISABLED=1
    $deadline = microtime(true) + 5;
    while ($cam->snap->verdict(new \Camada\Snapshot\MatchInput(ip: '0.0.0.0'))->reason === 'cold' && microtime(true) < $deadline) {
        $cam->snap->refresh();                // bounded: an unreachable analyst leaves it cold, and the app still fails open
        usleep(10_000);
    }
}
```

## What it does per request

1. Keeps the snapshot fresh (above): ETag/304 and gzip on the wire, at the cadence your tenant
   config sets (`poll_seconds`). Every poll and event batch carries `x-camada-sdk:
   @camada/php/<version>`, and polls ask for snapshot v5 (`x-camada-snapshot: 5`) — the
   container that carries your ordered custom rules.
2. Resolves the client from the socket peer (`$_SERVER['REMOTE_ADDR']`), combined with
   `X-Forwarded-For` only under your tenant's trusted-proxy config (or `CAMADA_TRUSTED_PROXY`
   locally). A forwarded header on its own is never the ip: any caller can set it. Note that
   nginx's `real_ip` module rewrites `REMOTE_ADDR` before PHP sees it; behind it the peer is
   already the client and the trusted-proxy config should say `none`.
3. Enforces before anything else, beacon endpoints included: your ordered custom rules first (first
   match wins; they read ip, path, user-agent and request headers), then allow → block → challenge.
   A block answers `403 Forbidden` with `x-block-reason`, `x-block-version` and, when a rule
   decided, `x-block-rule`; its event ships with `blk` (and `rl`). A `warn` rule passes and stamps
   `wrn`; a `skip` rule passes with nothing stamped. Cold (no snapshot yet) passes: fail open.
4. Challenge: a `challenge` verdict gets the self-contained proof-of-work page (or 403 JSON for a
   non-HTML request); `POST /__camada/challenge` verifies the solution, sets `_cch` (bound to the
   ip, one hour) and 302s back. A request whose ip cannot be resolved is never challenged.
5. Serves the beacon: `GET /_cam/b.js` (the `@camada/browser` build, vendored as a class constant
   and served from opcache) and `POST /_cam/fp` (≤ 32 KB, relayed onto the event batch as a
   `sig: 1` row with the ip camada resolved). Both fall through to your app when the tenant
   switched the beacon off.
6. Runs your app with `x-rid` and the `_sfp` session cookie on its response, and when the response
   is done ships one redacted event: method, host, path, scrubbed query, status, latency, header
   names/sizes/order, the auth scheme (never the credential), cookie count (never values). An
   uncaught exception in your app ships as `st: 500` and stays PHP's (or Laravel's) own 500.

## Options

`new Camada(...)` named arguments; everything credential-shaped comes from the environment.

| option | default | meaning |
|---|---|---|
| `env` | the process environment | where `CAMADA_*` are read from |
| `transport` | `StreamTransport` | the HTTP seam that reaches the analyst (tests inject a fake) |
| `refreshS` | server-steered | poll cadence; set, it is pinned |
| `challenge` | `true` | serve the proof-of-work page for challenge verdicts (`CAMADA_CHALLENGE=0` too) |
| `challengePath` | `/__camada/challenge` | where the page posts its solution |
| `snapshotVersion` | `5` | 4 drops your custom rules; 3 the allow/challenge sides too |
| `scriptPath` / `fpPath` | `/_cam/b.js` / `/_cam/fp` | the beacon endpoints; keep them in one directory |

Env: `CAMADA_KEY` (or `CAMADA_TOKEN` + `CAMADA_SNAPSHOT_TOKEN`), `CAMADA_INGEST_URL`,
`CAMADA_SNAPSHOT_URL`, `CAMADA_TRUSTED_PROXY` (`none | vercel | hops:N | cidrs:a,b`),
`CAMADA_CACHE_DIR`, `CAMADA_CHALLENGE=0`, and the kill switch `CAMADA_DISABLED=1` (checked per
request; set at boot, no files are touched and no request is ever made).

## The first-party beacon

```php
echo '<html><head>', $cam->scriptTag($ctx), '</head>…';
```

The tag is `<script src="/_cam/b.js?r=<rid>" async>`, so the beacon joins the page view that
served it. Move both paths with `scriptPath` / `fpPath` when `/_cam/` is not yours; the script
derives the post path from its own URL, so the two must share a directory.

## App-context events

```php
$cam->track($ctx, 'login_failed', $email);
```

The identifier is HMAC-hashed in-process with your ingest token; the raw value never reaches the
spool. `track()` never throws and is a no-op on a request the adapter did not run for (an inert
context). The event name is free-form; the analyst's app-context rules read this vocabulary:

| event | when |
|---|---|
| `login_failed` / `login_succeeded` | a login attempt settled; pass the user so attempts per account can be counted |
| `signup` | an account was created |
| `password_reset` | a reset was requested |
| `mfa_failed` | a second factor was rejected |
| `payment_failed` / `payment_succeeded` | a payment authorisation settled |
| `coupon_failed` | a promo/voucher code was rejected |

A route you gate yourself: `$cam->serveChallenge($ctx)` returns the page as an `Answer` to hand
to `Sapi::send()` (and then `return`) until the browser holds a valid `_cch`, then `null`.

## What this tap can see

`sdk-php` is an in-app tap: status, latency, session, the beacon's browser signals and your
outcomes. Header order is whatever `getallheaders()` yields — a hash under FastCGI — so the
analyst reads no HEADER_ORDER signal from this tap; it never scores the absence of header order,
ASN, country or a TLS fingerprint against a request, and resolves ASN and country itself.
Enforcement at this position covers ip, path, user-agent and header conditions — ASN, country
and TLS entries fail open in-app. `matches` patterns are JS regexes read by PCRE without the `u`
flag (named groups and `\cX` are native, `[^]` is translated, `\d`/`\w`/`\b` stay ASCII); a
spelling PCRE still rejects never matches here, while it does at the edge.

## Deploying it

- FPM, FrankenPHP (classic mode), LiteSpeed: the response ends with `fastcgi_finish_request()`
  and the post-response work runs in the same worker afterwards — a slow analyst costs that
  worker's availability for the poll's duration (3 s timeout), never the client's latency.
- `php -S`, mod_php: the fallback flushes the adapter's buffer with a `Content-Length`; a client
  that honours it (browsers, curl, node) stops reading before the deferred work runs. Run the CLI
  server with `PHP_CLI_SERVER_WORKERS=4` or more, or a refresh in one request delays the next.
  With `zlib.output_compression=On` the response ends with the script instead (PHP's compressing
  buffer cannot be ended early), so the deferred work adds to that request's wall time there.
- A fleet polls once per host per cadence (the tenant's `poll_seconds`), and each host ships its
  own spool: a failed POST drops that batch (logged at most once a minute). Nothing runs at
  process exit and no signal handlers are installed.
- Worker-mode SAPIs (FrankenPHP worker mode, Octane), a PSR-15 middleware and an APCu-backed
  runtime are deferred: the file-backed runtime is the one runtime today. Under Laravel the
  middleware's `terminate()` is the post-response phase (an Answer's ship and refresh ride it
  too), so Octane runs it per request, but that path is untested here; its 403 is sent as
  `text/plain; charset=utf-8`, the charset Symfony's `prepare()` adds.

## Fail open

Every entry point runs inside the fail-open envelope: a dead ingest drops telemetry (logged at
most once a minute, across workers), a corrupt snapshot keeps the previous one, a bug in the
package costs the request its join, never its response. `CAMADA_DISABLED=1` bypasses everything.

## Development

```
composer install && composer lint && composer fmt && composer test
```

The suite reads the golden snapshot fixtures from the `camada-core` sibling checkout (or
`CAMADA_FIXTURES_DIR`) and runs every case over both word sources — the seeking one a request
uses and the in-memory one — which is what proves the seeking matcher equals the reference. It
pins the vendored beacon to `camada-browser/dist/auto.global.js` (`npm run build` there first,
then `php scripts/sync-beacon.php` after a beacon release). Both fail by name when the checkout
is missing rather than skipping. The SAPI suite drives the adapter over a real `php -S`.

[`camada-php-example`](../camada-php-example) is the hand-test bench (`php -S` on :3005), and
`node scripts/e2e-sdk-php.mjs` in `camada/edge-analyst` drives it against a seeded local analyst
over real HTTP, cold first request included.
