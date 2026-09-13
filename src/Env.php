<?php

declare(strict_types=1);

namespace Camada;

/**
 * Environment wiring. The two-line quickstart depends on this doing the right thing:
 *   CAMADA_KEY=<ingest_token>.<snap_token>   (printed by `reconcile instructions` and seed)
 *   CAMADA_INGEST_URL / CAMADA_SNAPSHOT_URL  (dev: http://localhost:8787[/snapshot])
 *   CAMADA_DISABLED=1                        kill switch, checked at boot and per request
 *   CAMADA_TRUSTED_PROXY                     local override: none | vercel | hops:N | cidrs:a,b
 *   CAMADA_CHALLENGE=0                       do not enforce challenge verdicts
 *   CAMADA_CACHE_DIR                         where the shared snapshot and spool live (default: the system temp dir)
 *
 * @phpstan-import-type TrustedProxy from Config
 */
final class Env
{
    /** PLACEHOLDER default, the same one @camada/node carries — confirm the production ingest domain before any Packagist publish. */
    public const DEFAULT_INGEST_URL = 'https://in.camada.dev';

    /**
     * @param TrustedProxy|null $trustedProxy null = defer to server-delivered config
     */
    private function __construct(
        public readonly string $ingestToken,
        public readonly string $snapToken,
        public readonly string $secret,        // HMAC key for the challenge nonce/cookie — never leaves the process
        public readonly string $ingestUrl,
        public readonly string $snapshotUrl,
        public readonly ?array $trustedProxy,
        public readonly ?string $cacheDir,     // CAMADA_CACHE_DIR; null = the system temp dir keyed by the snapshot token
    ) {
    }

    /**
     * null (SDK stays inert, one log line) rather than throwing on bad config.
     *
     * @param array<string, mixed> $env
     */
    public static function resolve(array $env): ?self
    {
        $get = static fn (string $k): ?string => isset($env[$k]) && is_string($env[$k]) && $env[$k] !== '' ? $env[$k] : null;
        $key = Config::parseKey($get('CAMADA_KEY'));
        $ingestToken = $key !== null ? $key[0] : $get('CAMADA_TOKEN');
        $snapToken = $key !== null ? $key[1] : $get('CAMADA_SNAPSHOT_TOKEN');
        if ($ingestToken === null || $snapToken === null) {
            return null;
        }
        $ingestUrl = rtrim($get('CAMADA_INGEST_URL') ?? self::DEFAULT_INGEST_URL, '/');
        return new self(
            ingestToken: $ingestToken,
            snapToken: $snapToken,
            secret: $get('CAMADA_KEY') ?? "{$ingestToken}.{$snapToken}",
            ingestUrl: $ingestUrl,
            snapshotUrl: $get('CAMADA_SNAPSHOT_URL') ?? "{$ingestUrl}/snapshot",
            trustedProxy: Config::parseTrustedProxyEnv($get('CAMADA_TRUSTED_PROXY')),
            cacheDir: $get('CAMADA_CACHE_DIR'),
        );
    }
}
