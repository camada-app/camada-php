<?php

declare(strict_types=1);

namespace Camada;

/**
 * Configuration shapes shared by the client and the engine. `parseKey` splits CAMADA_KEY, and
 * `remoteConfig` is what GET /snapshot hands back in x-camada-config (whitelisted server-side):
 * { tenant, beacon, sample, exclude[], trusted_proxy, poll_seconds }.
 *
 * A trusted-proxy config mirrors the server-validated tenant config (edge-analyst src/tenant-config.js):
 * {mode: none} | {mode: hops, hops: N} | {mode: cidrs, cidrs: [...]} | {mode: vercel}.
 *
 * @phpstan-type TrustedProxy array{mode: string, hops?: int, cidrs?: list<string>}
 * @phpstan-type RemoteConfig array<string, mixed>
 */
final class Config
{
    /**
     * CAMADA_KEY is `<ingest_token>.<snap_token>` (printed by reconcile instructions and seed).
     *
     * @return array{string, string}|null
     */
    public static function parseKey(?string $key): ?array
    {
        if ($key === null || $key === '') {
            return null;
        }
        $dot = strpos($key, '.');
        if ($dot === false || $dot === 0 || $dot === strlen($key) - 1) {
            return null;
        }
        return [substr($key, 0, $dot), substr($key, $dot + 1)];
    }

    /**
     * CAMADA_TRUSTED_PROXY: none | vercel | hops:N | cidrs:a,b. Unset or malformed returns null,
     * which callers treat as "defer to the server-delivered tenant config", never as trust.
     *
     * @return TrustedProxy|null
     */
    public static function parseTrustedProxyEnv(?string $v): ?array
    {
        if ($v === null || $v === '') {
            return null;
        }
        if ($v === 'none' || $v === 'vercel') {
            return ['mode' => $v];
        }
        if (str_starts_with($v, 'hops:')) {
            $n = substr($v, 5);
            if (preg_match('/^-?\d+$/', $n) !== 1) {
                return null;
            }
            $hops = (int) $n;
            return $hops >= 1 ? ['mode' => 'hops', 'hops' => $hops] : null;
        }
        if (str_starts_with($v, 'cidrs:')) {
            $cidrs = array_values(array_filter(array_map('trim', explode(',', substr($v, 6))), static fn (string $c): bool => $c !== ''));
            return $cidrs !== [] ? ['mode' => 'cidrs', 'cidrs' => $cidrs] : null;
        }
        return null;
    }

    /**
     * The parsed x-camada-config header; anything but a JSON object is ignored (previous kept).
     *
     * @return RemoteConfig|null
     */
    public static function remoteConfig(mixed $raw): ?array
    {
        if (!is_array($raw) || ($raw !== [] && array_is_list($raw))) {
            return null;
        }
        /** @var array<string, mixed> $raw */
        return $raw;
    }
}
