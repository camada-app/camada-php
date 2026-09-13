<?php

declare(strict_types=1);

namespace Camada;

use Camada\Challenge\Format;
use Camada\Challenge\Kit;
use Camada\Challenge\Page;
use Camada\Events\Builder;
use Camada\Events\Spool;
use Camada\Runtime\Cache;
use Camada\Runtime\Deferred;
use Camada\Snapshot\Client;
use Camada\Snapshot\MatchInput;
use Camada\Transport\StreamTransport;
use Camada\Transport\TransportInterface;

/**
 * The engine: the host-neutral request handling every adapter delegates to (the PHP twin of
 * camada-python's engine.py). An adapter turns its request into a Req, asks wantsBody() and
 * reads at most that many bytes, then calls handle(): an Answer means camada fully answered the
 * request (block, challenge, verify, beacon endpoints); a Passed means run the app, stamp the
 * rid header and session cookie on its response, and call onFinish(status) once when it is
 * done. Everything runs inside the fail-open envelope: a camada bug must never 5xx the customer,
 * and CAMADA_DISABLED=1 bypasses the SDK entirely.
 *
 * PHP has no long-lived process, so the poll thread and the flush thread of the Python SDK are
 * ONE file-backed runtime every worker shares (Runtime\Cache): the request path reads state.json
 * and seeks into the cached container, never opens a socket, and arms the post-response phase
 * (Runtime\Deferred) — FINISH the event, SHIP a due spool, REFRESH a stale snapshot — which the
 * adapter runs after the client has its bytes.
 *
 * @phpstan-import-type TrustedProxy from Config
 */
class Camada
{
    private static ?self $default = null;

    public readonly ?Env $env;
    public readonly ?Client $snap;
    public readonly ?Spool $spool;
    public readonly ?Kit $kit;
    public readonly bool $challengeOn;
    private readonly bool $killed;
    private readonly Deferred $deferred;

    /**
     * @param array<string, mixed>|null $env where CAMADA_* are read from (default: the process environment)
     * @param TransportInterface|null $transport threaded into the snapshot client and the event spool (tests inject a fake)
     * @param float|null $refreshS poll cadence; set, it is pinned (else the server's poll_seconds steers it)
     * @param bool $challenge enforce `challenge` verdicts with the first-party page (CAMADA_CHALLENGE=0 also off)
     * @param int $snapshotVersion 5 carries the custom rules; 4 the sides only; 3 opts out of both
     */
    public function __construct(
        ?array $env = null,
        ?TransportInterface $transport = null,
        ?float $refreshS = null,
        public readonly string $scriptPath = Constants::SCRIPT_PATH,
        public readonly string $fpPath = Constants::FP_PATH,
        bool $challenge = true,
        public readonly string $challengePath = Constants::CHALLENGE_PATH,
        int $snapshotVersion = Constants::DEFAULT_SNAPSHOT_VERSION,
    ) {
        $source = $env ?? array_merge($_ENV, getenv());
        $this->challengeOn = $challenge && ($source['CAMADA_CHALLENGE'] ?? null) !== '0';
        $this->killed = ($source[Constants::KILL_SWITCH_ENV] ?? null) === '1';
        $this->env = Env::resolve($source);
        $this->deferred = new Deferred();
        if ($this->env === null || $this->killed) {   // unconfigured or killed at boot: no files, no requests, truly silent
            $this->snap = null;
            $this->spool = null;
            $this->kit = null;
            return;
        }
        $cache = new Cache(Cache::defaultDir($this->env->snapToken, $this->env->cacheDir));
        Guarded::useStamp($cache->path('log.stamp'));   // one log line a minute across every worker, not per process
        $transport ??= new StreamTransport();
        $this->snap = new Client($this->env->snapshotUrl, $this->env->snapToken, $cache, $transport, sdk: Version::SDK_ID, snapshotVersion: $snapshotVersion, refreshS: $refreshS);
        $this->spool = new Spool($cache, $transport, $this->env->ingestUrl, $this->env->ingestToken, sdk: Version::SDK_ID);
        $this->kit = new Kit($this->env->secret);
    }

    // ---- the default engine ----

    /** The lazy singleton wired from the environment on first use (what Sapi::run() and the Laravel middleware share). */
    public static function default(): self
    {
        if (self::$default === null) {
            self::$default = new self();
            if (self::$default->env === null) {
                Guarded::log('CAMADA_KEY (or CAMADA_TOKEN + CAMADA_SNAPSHOT_TOKEN) not set — camada is inactive');
            }
        }
        return self::$default;
    }

    /** Replaces the default engine — for tests and explicit wiring (null resets to lazy). */
    public static function setDefault(?self $engine): void
    {
        self::$default = $engine;
    }

    public static function nowMs(): int
    {
        return Builder::nowMs();
    }

    public function disabled(): bool
    {
        return $this->env === null || $this->killed;
    }

    /** The post-response phase of the current request: the adapter installs and runs it. */
    public function deferred(): Deferred
    {
        return $this->deferred;
    }

    /** @return TrustedProxy|null */
    private function trustedProxy(): ?array
    {
        if ($this->env !== null && $this->env->trustedProxy !== null) {
            return $this->env->trustedProxy;   // explicit local override wins
        }
        $cfg = $this->snap?->config()['trusted_proxy'] ?? null;
        if (!is_array($cfg) || !is_string($cfg['mode'] ?? null)) {
            return null;
        }
        /** @var TrustedProxy $cfg */
        return $cfg;
    }

    private function beaconEnabled(): bool
    {
        return $this->snap !== null && ($this->snap->config()['beacon'] ?? null) !== false;
    }

    private function ip(Req $req): ?string
    {
        return Ip::resolve($req->peer, $req->header('x-forwarded-for'), $this->trustedProxy());
    }

    private static function cookieValue(?string $cookie, string $name): ?string
    {
        $src = '; ' . ($cookie ?? '');
        $i = strpos($src, '; ' . $name . '=');
        if ($i === false) {
            return null;
        }
        $start = $i + strlen($name) + 3;
        $j = strpos($src, ';', $start);
        return $j === false ? substr($src, $start) : substr($src, $start, $j - $start);
    }

    private static function uuid(): string
    {
        $b = random_bytes(16);
        $b[6] = chr((ord($b[6]) & 0x0f) | 0x40);
        $b[8] = chr((ord($b[8]) & 0x3f) | 0x80);
        $h = bin2hex($b);
        return substr($h, 0, 8) . '-' . substr($h, 8, 4) . '-' . substr($h, 12, 4) . '-' . substr($h, 16, 4) . '-' . substr($h, 20);
    }

    // ---- the adapter contract ----

    /** The byte cap to read the body under, when camada itself may answer this request. */
    public function wantsBody(string $method, string $path): ?int
    {
        if ($this->disabled() || $method !== 'POST') {
            return null;
        }
        if ($path === $this->fpPath && $this->beaconEnabled()) {
            return Constants::FP_MAX;
        }
        if ($path === $this->challengePath && $this->challengeOn) {
            return Constants::BODY_MAX;
        }
        return null;
    }

    /**
     * Never throws. `$body` is the request body when wantsBody() asked for one, or null when the
     * adapter refused to read it (declared or actual size over the cap).
     */
    public function handle(Req $req, ?string $body = null): Answer|Passed
    {
        try {
            return $this->decide($req, $body);
        } catch (\Throwable $err) {   // a camada bug costs the join, never the request
            Guarded::log($err);
            return Passed::inert();
        }
    }

    protected function decide(Req $req, ?string $body): Answer|Passed
    {
        if ($this->disabled() || $this->snap === null || $this->spool === null || $this->env === null) {
            return Passed::inert();
        }
        $snap = $this->snap;
        $spool = $this->spool;
        $t0 = microtime(true);
        // One state read per request, then the post-response phase: the spool ships when due, the
        // snapshot refreshes when stale — never on the request path.
        $snap->invalidate();
        $this->deferred->arm(Deferred::SHIP, static fn () => $spool->shipIfDue());
        if ($snap->stale()) {
            $this->deferred->arm(Deferred::REFRESH, static fn () => $snap->refresh());
        }
        $ip = $this->ip($req);

        // Enforce before anything else, beacon endpoints included — fail open while cold. The
        // custom rules read the user agent and the request headers (§D3).
        $v = $snap->verdict(new MatchInput(ip: $ip, path: $req->path, ua: $req->header('user-agent'), header: $req->header(...)));
        if ($v->block) {
            $headers = [['content-type', 'text/plain'], ['x-block-reason', $v->reason ?? ''], ['x-block-version', $v->version ?? '']];
            if ($v->rule !== null) {
                $headers[] = ['x-block-rule', $v->rule];   // a custom rule blocked: name it, so the customer knows which row to edit
            }
            $ev = $this->event($req, self::uuid(), null, false, $ip);
            $ev['st'] = 403;   // blocked requests always ship: silent expiry makes blocks oscillate
            $ev['blk'] = $v->reason;   // the reason rides the event so the analyst counts SDK blocks, not the app's own 403s
            if ($v->rule !== null) {
                $ev['rl'] = $v->rule;
            }
            $spool->push($ev);
            return new Answer(403, $headers, 'Forbidden');
        }
        // `warn` passes the request and only marks its event (below, on finish); a skip passes
        // with nothing stamped at all — it is the absence of enforcement.

        // A challenge needs a resolved client IP: the nonce and the _cch cookie are bound to it,
        // so without one a single solve would mint a cookie every unidentified client could
        // present. No ip -> no challenge (fail open), the same stance ip rules take.
        if ($this->challengeOn && $ip !== null && $ip !== '') {
            // The verify endpoint answers first: a challenged client must be able to reach it.
            if ($req->method === 'POST' && $req->path === $this->challengePath) {
                return $this->verify($req, $body, $ip);
            }
            if ($v->challenge && !$this->challengePassed($req, $ip)) {
                return $this->challengeAnswer($req, $ip, self::cookieValue($req->header('cookie'), Constants::SESSION_COOKIE));
            }
        }

        if ($this->beaconEnabled()) {
            if ($req->method === 'GET' && $req->path === $this->scriptPath) {
                return new Answer(200, [['content-type', 'application/javascript'], ['cache-control', 'public, max-age=3600']], BeaconJs::JS);
            }
            if ($req->method === 'POST' && $req->path === $this->fpPath) {
                return $this->relayBeacon($body, $ip);
            }
        }

        $rid = self::uuid();
        $sid = self::cookieValue($req->header('cookie'), Constants::SESSION_COOKIE);
        $newSession = $sid === null || $sid === '';
        $setCookie = null;
        if ($newSession) {
            $sid = self::uuid();
            $setCookie = Constants::SESSION_COOKIE . '=' . $sid . '; Path=/; Max-Age=' . Constants::SESSION_MAX_AGE . '; HttpOnly; SameSite=Lax';
            if ($req->https || $req->header('x-forwarded-proto') === 'https') {
                $setCookie .= '; Secure';
            }
        }
        $ctx = new Context(rid: $rid, sid: $sid, ip: $ip, req: $req, engine: $this);

        $cfg = $snap->config() ?? [];
        $excluded = false;
        foreach (is_array($cfg['exclude'] ?? null) ? $cfg['exclude'] : [] as $x) {
            if (is_string($x) && str_starts_with($req->path, $x)) {
                $excluded = true;
            }
        }
        $sample = $cfg['sample'] ?? null;
        $rate = is_int($sample) || is_float($sample) ? (float) $sample : 1.0;
        $sampled = mt_rand() / mt_getrandmax() < $rate;   // sampling, not crypto
        $warnRule = $v->warn ? $v->rule : null;

        $onFinish = function (int $status) use ($req, $rid, $sid, $newSession, $ip, $ctx, $excluded, $sampled, $warnRule, $t0, $spool): void {
            try {
                // serveChallenge() may have answered from inside the app, and it already shipped
                // the `blk: "challenge"` row — one request, one event.
                if ($ctx->challenged || $excluded || !$sampled) {
                    return;
                }
                $ev = $this->event($req, $rid, $sid, $newSession, $ip);
                $ev['st'] = $status;
                $ev['dur'] = (int) ((microtime(true) - $t0) * 1000);
                if ($req->route !== null && $req->route !== '') {
                    $ev['rt'] = $req->route;
                }
                if ($warnRule !== null) {
                    $ev['wrn'] = $warnRule;   // §D3: the warn rule that let this request through
                }
                $spool->push($ev);
            } catch (\Throwable $err) {
                Guarded::log($err);
            }
        };
        return new Passed($rid, $setCookie, $ctx, $onFinish);
    }

    /** @return array<string, mixed> */
    private function event(Req $req, string $rid, ?string $sid, bool $newSession, ?string $ip): array
    {
        return Builder::wireEvent($req, $ip, Constants::TAP, $rid, $sid, $newSession);
    }

    // ---- beacon ----

    /**
     * Answers 204, and spools the beacon as a `sig: 1` row with the trusted-proxy-resolved
     * client IP: it rides the next event batch. Junk bodies are dropped, never shipped.
     */
    private function relayBeacon(?string $body, ?string $ip): Answer
    {
        if ($body === null) {
            return new Answer(413, [], '');
        }
        $answer = new Answer(204, [['cache-control', 'no-store']], '');
        $parsed = json_decode($body, true);
        if (!is_array($parsed) || ($parsed !== [] && array_is_list($parsed))) {
            return $answer;
        }
        $this->spool?->push(array_merge($parsed, ['sig' => 1, 'ip' => $ip, 'tap' => Constants::TAP]));   // spread first: ip and tap are the server's word
        return $answer;
    }

    /** For HTML templates: the first-party beacon tag with the request's rid. */
    public function scriptTag(?Context $ctx): string
    {
        if ($this->disabled() || !$this->beaconEnabled()) {
            return '';
        }
        $rid = $ctx?->rid;
        return '<script src="' . $this->scriptPath . ($rid !== null && $rid !== '' ? '?r=' . $rid : '') . '" async></script>';
    }

    // ---- challenge ----

    private function challengePassed(Req $req, ?string $ip): bool
    {
        return $this->kit !== null && $this->kit->tokenValid($ip, self::nowMs(), self::cookieValue($req->header('cookie'), Format::CHALLENGE_COOKIE));
    }

    private function page(string $ip, string $to): Answer
    {
        if ($this->kit === null) {
            throw new \LogicException('camada: no challenge kit');
        }
        $html = Page::render($this->kit->nonce($ip, self::nowMs()), $this->challengePath, $to);
        return new Answer(403, [['content-type', 'text/html; charset=utf-8'], ['cache-control', 'no-store'], ['x-camada-challenge', '1']], $html);
    }

    /**
     * 403 + the proof-of-work page (HTML navigations) or 403 JSON (everything else), plus the
     * `blk: "challenge"` event — a served challenge is reported like a block (contract §D2).
     */
    private function challengeAnswer(Req $req, string $ip, ?string $sid): Answer
    {
        $to = Format::safeReturnTo($req->path . $req->query);
        if (Format::wantsHtml($req->header('accept'), $req->header('sec-fetch-dest'))) {
            $answer = $this->page($ip, $to);
        } else {
            $answer = new Answer(403, [['content-type', 'application/json'], ['cache-control', 'no-store'], ['x-camada-challenge', '1']], '{"error":"challenge_required"}');
        }
        try {
            $ev = $this->event($req, self::uuid(), $sid, false, $ip);
            $ev['st'] = 403;
            $ev['blk'] = 'challenge';
            $this->spool?->push($ev);
        } catch (\Throwable $err) {   // the response is decided; telemetry must never undo that
            Guarded::log($err);
        }
        return $answer;
    }

    /**
     * POST from the challenge page: validate the nonce and the proof of work, set _cch, 302
     * back to the (sanitised, same-site) original URL, and ship `{ st: 200, ch: 1 }`.
     */
    private function verify(Req $req, ?string $body, string $ip): Answer
    {
        if ($this->kit === null) {
            throw new \LogicException('camada: no challenge kit');
        }
        if ($body === null) {
            return new Answer(413, [], '');
        }
        $form = Format::parseFormBody($body);
        $to = Format::safeReturnTo($form['to'] ?? null);
        $now = self::nowMs();
        if (!$this->kit->verify($ip, $now, $form['nonce'] ?? null, $form['solution'] ?? null)) {
            return $this->page($ip, $to);
        }
        $secure = $req->https || $req->header('x-forwarded-proto') === 'https';
        $cookie = Format::challengeCookie($this->kit->issue($ip, $now), $secure);
        $ev = $this->event($req, self::uuid(), self::cookieValue($req->header('cookie'), Constants::SESSION_COOKIE), false, $ip);
        $ev['st'] = 200;
        $ev['ch'] = 1;   // challenge passed (contract §A3 ingest field)
        $this->spool?->push($ev);
        return new Answer(302, [['location', $to], ['set-cookie', $cookie], ['cache-control', 'no-store']], '');
    }

    /**
     * Serve the challenge for this request on demand — for a route the app wants to gate
     * itself. Null when the client already holds a valid _cch (render your own page), or when
     * the client cannot be identified (fail open).
     */
    public function serveChallenge(?Context $ctx): ?Answer
    {
        try {
            if ($this->disabled() || $this->kit === null || $ctx === null) {
                return null;
            }
            $req = $ctx->req;
            $ip = $ctx->ip;
            if ($req === null || $ip === null || $ip === '' || $this->challengePassed($req, $ip)) {
                return null;
            }
            $ctx->challenged = true;
            return $this->challengeAnswer($req, $ip, $ctx->sid);
        } catch (\Throwable $err) {
            Guarded::log($err);
            return null;
        }
    }

    // ---- app-context events ----

    /**
     * App-context outcome events (login failed, signup, ...). The identifier is HMAC-hashed
     * in-process; the raw value never reaches the spool. Never throws; a no-op without an engine.
     */
    public function track(?Context $ctx, string $event, ?string $user = null): void
    {
        try {
            if ($this->disabled() || $this->spool === null || $this->env === null) {
                return;
            }
            $uid = $user !== null && $user !== '' ? Redact::hashUserId($user, $this->env->ingestToken) : null;
            $this->spool->push([
                'tap' => Constants::TAP, 'et' => $event, 'uid' => $uid,
                'rid' => $ctx?->rid, 'sid' => $ctx?->sid, 'ip' => $ctx?->ip, 'ts' => self::nowMs(),
            ]);
        } catch (\Throwable $err) {
            Guarded::log($err);
        }
    }
}
