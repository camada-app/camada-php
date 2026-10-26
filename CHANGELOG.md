# Changelog

## 0.2.0 - 2026-10-26

- fix (security): snapshot meta `pathsRegex` entries are now tested like a path `matches` rule condition, and inside the request's regex budget shared with the rule walk. They are case-insensitive, a pattern this SDK refuses never matches, and a path over 2048 chars, an engine failure or a spent budget answers block. Previously they ran outside the budget, and a failure was a miss. `Snapshot::$pathsRegex` is now a list of closures. (camada-all-rvuh)
- feat: the first-party beacon relay (/_cam/fp) stamps `rts`, the relay's clock in epoch ms, on the sig:1 row (overwriting any browser-supplied `rts`), so the analyst can place the beacon on the same clock as the request rows. (camada-all-wd3b)
- fix: a signalled response (`x-camada-challenge: 1`) now also sets `cdn-cache-control`, `surrogate-control`, `cloudflare-cdn-cache-control`, `vercel-cdn-cache-control` and `netlify-cdn-cache-control` to `no-store`, overriding the app's. CDNs read those ahead of `cache-control`, so an app-set one could still let a shared cache keep the per-client copy. (camada-all-1zlg)
- feat: a non-HTML request (fetch/XHR/API) under a `challenge` row no longer gets a 403 JSON `challenge_required`: it passes to the app with `x-camada-challenge: 1` and `cache-control: no-store` (replacing the app's own), and its normal event ships with `chs: 1` even when the path is excluded or the request is sampled out. A page load still gets the challenge page. `serveChallenge()` returns null for a non-HTML request and signals it the same way. New `Context::$signalled`. (camada-all-7cgs)
- fix (security): the first-party beacon relay (/_cam/fp) drops SDK-attested keys (tlsx, ja4, asn, cc, sid, ns, st, dur, rt, blk, rl, wrn, chs, ch, et, uid) from the visitor's body before queuing the sig:1 row, so a visitor cannot forge them; the analyst joins those from the request row. (camada-all-q617)
- fix: a path condition tests each distinct spelling of the request path once, so an already-canonical path no longer runs (and spends the request's regex budget on) the same regex up to three times. (camada-all-p3zg)
- fix (security): a `matches` regex with a `:`, `=` or `.` in a character class that PCRE read as POSIX syntax (`x[:alpha:]y`, `x[.a.]y`, `x[=a=]y`, also beside `\s`) used to fail to compile, so the rule never matched (failing open). Those characters are now escaped inside a class, so the rule matches as JS reads it: `[:alpha:]` is the set {`:` `a` `l` `p` `h`}. Deny rules that never fired on this SDK can start firing after upgrade. (camada-all-tv0m)

## 0.1.5 - 2026-10-19

- fix (security): a custom-rule `matches` regex never runs on a ua, header or path value over 2048 chars (UTF-16 units): over-cap fails closed, a hit for block/challenge/warn and a miss for skip/allow, never truncated (truncation would fail a deny rule open). (camada-all-q980)
- fix (security): control characters never reach the matcher alone: a ua/header value carrying `[\x00-\x1f\x7f]` is tested raw and stripped for deny rules (a pattern that targets `\t` or `\x00` still fires), and never matches a skip/allow rule, so stripping cannot widen an exemption such as `^partner-[a-z]+$` on `partner-acme\n`. The raw path form %-encodes the same characters. (camada-all-q980, camada-all-wh9m)
- fix (security): a regex engine failure fails closed: `preg_match` returning `false` at the backtrack/JIT limit on a value under the cap is a hit for deny rules and a miss for skip/allow, for ua/header and path `matches` (it used to read as no match). The canonical-path fast path uses the `D` modifier, so `$` no longer matches before a trailing newline. (camada-all-5jpb)
- test: the shared blk5 conformance vectors (RC01-RC47, contract regex-cap-sdk v3) run against `../camada-core/test/fixtures`.

## 0.1.4 - 2026-10-12

- feat: `unixSocketListener` option for nginx on a unix socket (`REMOTE_ADDR` `unix:`); the CSP is written in a single pass.
- fix (security): under trusted proxy `cidrs`, `X-Forwarded-For` is no longer believed from a socket peer that is not a trusted proxy: such a peer is the client. Before this, anyone reaching the origin directly could pick their own client ip, slip past an ip block or get another ip blocked. A loopback peer counts as a trusted hop; with no peer the walk is unchanged. (camada-all-yfc6)
- fix: `X-Forwarded-For` entries with a port (`203.0.113.66:51234`, `[2001:db8::66]:51234`) resolve to the address in every mode. (camada-all-0vho)
- fix: `ref` no longer ships the Referer verbatim: its query and fragment go through the query scrub. (camada-all-ijsa)
- fix: the challenge page sends its own `Content-Security-Policy` (inline solver by hash, no `form-action`) and replaces a policy already on the response, so a strict app CSP no longer blocks the solver or the post-solve redirect; the solver reads the nonce from the form. (camada-all-y38o)
- fix: a block 403 sends `Cache-Control: no-store` and replaces a `Cache-Control` set upstream, so a shared cache or CDN no longer keeps one visitor's block for others. (camada-all-8lp6)
- fix (security): the resolved ip is always a valid address or none (C6 v3): a non-ip peer never walks `X-Forwarded-For`, entries are trimmed of SP/HTAB only, `::ffff:a.b.c.d` is unmapped, malformed IPv6 is rejected. The query scrub percent-decodes bytewise (up to 4 passes, no `+`) before testing and tests bare and nested parts.
- chore: beacon re-synced to `@camada/browser` 0.3.2.
