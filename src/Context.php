<?php

declare(strict_types=1);

namespace Camada;

/**
 * What the app sees of a request camada let through: the request id the response carries
 * (`x-rid`), the session id (`_sfp`), the client ip camada resolved, the normalised request
 * (whose `route` the host may fill in before the event ships) and the engine that produced it
 * (`scriptTag`, `track` and `serveChallenge` resolve through it). `inert()` is the context of a
 * request the SDK did not run for: every helper stands down silently on it.
 */
final class Context
{
    /** Set to `no-store` on a signalled response: CDNs read their own cache header ahead of cache-control. */
    public const NO_STORE_HEADERS = ['cache-control', 'cdn-cache-control', 'surrogate-control', 'cloudflare-cdn-cache-control', 'vercel-cdn-cache-control', 'netlify-cdn-cache-control'];

    /** Set by serveChallenge(): the challenge row already shipped, so onFinish ships nothing. */
    public bool $challenged = false;

    /**
     * A non-HTML request passed under a challenge: the response carries `x-camada-challenge: 1` and
     * `no-store` on every cache header, and its event `chs: 1`. Adapters read it when the response headers are written,
     * since serveChallenge() can set it from inside the app.
     */
    public bool $signalled = false;

    public function __construct(
        public readonly ?string $rid = null,
        public readonly ?string $sid = null,
        public readonly ?string $ip = null,
        public readonly ?Req $req = null,
        public readonly ?Camada $engine = null,
    ) {
    }

    public static function inert(): self
    {
        return new self();
    }
}
