<?php

declare(strict_types=1);

namespace Camada;

/**
 * Client-IP resolution under the tenant's trusted-proxy config. The default is the socket peer:
 * raw X-Forwarded-For is attacker-writable and is NEVER trusted without explicit configuration;
 * a spoofed XFF must not reach the analysis or the blocklist. Ported from @camada/core src/ip.ts.
 *
 * @phpstan-import-type TrustedProxy from Config
 * @phpstan-import-type Words from IpParse
 * @phpstan-type Cidr array{base4: int, base6: Words|null, bits: int}
 */
final class Ip
{
    /**
     * The client IP from the socket peer and X-Forwarded-For per the trusted-proxy config.
     * Anything unresolvable falls back to the peer (fail safe).
     *
     * XFF entries are read without a port (`ip:port`, `[v6]:port`, as Azure writes them) in every
     * mode (camada-all-0vho).
     *
     * `cidrs` (also what the dashboard's Cloudflare option stores) walks the chain `[...xff, peer]`
     * from the right (camada-all-yfc6): if the socket peer is not a trusted proxy, the request did
     * not come through one and the peer IS the client; XFF is ignored, since anyone hitting the
     * origin directly can write it. A loopback peer (127.0.0.0/8, ::1, ::ffff:127.x.x.x) counts as
     * a trusted hop: a local front end or sidecar, which no remote client can be. Loopback is
     * trusted only as the peer, never as an XFF entry. With no peer at all the walk runs over XFF
     * alone, as before: the host's network edge is trusted to have written it. `hops` and `vercel`
     * trust XFF by definition and do not look at the peer.
     *
     * @param TrustedProxy|null $cfg
     */
    public static function resolve(?string $peer, ?string $xff, ?array $cfg): ?string
    {
        $sock = $peer !== null && strncasecmp($peer, '::ffff:', 7) === 0 ? substr($peer, 7) : $peer;   // dual-stack v4-mapped form
        if ($cfg === null || $cfg['mode'] === 'none' || $xff === null || $xff === '') {
            return $sock;
        }
        $entries = array_values(array_filter(array_map(static fn (string $e): string => self::stripPort(trim($e)), explode(',', $xff)), static fn (string $e): bool => $e !== ''));
        if ($entries === []) {
            return $sock;
        }
        $candidate = null;
        $mode = $cfg['mode'];
        if ($mode === 'hops') {
            $hops = (int) ($cfg['hops'] ?? 0);
            if ($hops >= 1 && $hops <= count($entries)) {
                $candidate = $entries[count($entries) - $hops];
            }
        } elseif ($mode === 'vercel') {
            $candidate = $entries[count($entries) - 1];   // Vercel overwrites XFF, so its rightmost entry is trustworthy
        } elseif ($mode === 'cidrs') {
            $trusted = [];
            foreach ($cfg['cidrs'] ?? [] as $c) {
                $parsed = self::parseCidr($c);
                if ($parsed !== null) {
                    $trusted[] = $parsed;
                }
            }
            if ($sock !== null && !self::isLoopback($sock) && !self::trusted($sock, $trusted)) {
                return $sock;   // the peer is the first hop: no trusted proxy wrote this XFF
            }
            foreach (array_reverse($entries) as $entry) {
                if (!self::trusted($entry, $trusted)) {
                    $candidate = $entry;
                    break;
                }
            }
        }
        return $candidate !== null && self::validIp($candidate) ? $candidate : $sock;
    }

    /** @param list<Cidr> $trusted */
    private static function trusted(string $ip, array $trusted): bool
    {
        foreach ($trusted as $t) {
            if (self::inCidr($ip, $t)) {
                return true;
            }
        }
        return false;
    }

    /**
     * One X-Forwarded-For entry with any port removed: `[v6]:port` and `[v6]` → `v6`,
     * `a.b.c.d:port` → `a.b.c.d`. A bare IPv6 literal is returned whole (its last group is never a
     * port); anything else malformed comes back unchanged, so validation rejects it and the peer wins.
     */
    private static function stripPort(string $e): string
    {
        if (str_starts_with($e, '[')) {
            $close = strpos($e, ']');
            if ($close === false) {
                return $e;
            }
            $inner = substr($e, 1, $close - 1);
            $rest = substr($e, $close + 1);
            return str_contains($inner, ':') && ($rest === '' || preg_match('/^:\d{1,5}$/D', $rest) === 1) ? $inner : $e;
        }
        if (substr_count($e, ':') !== 1) {
            return $e;   // no colon, or a bare IPv6 literal
        }
        $colon = (int) strpos($e, ':');
        $host = substr($e, 0, $colon);
        return IpParse::ip4($host) >= 0 && preg_match('/^:\d{1,5}$/D', substr($e, $colon)) === 1 ? $host : $e;
    }

    /** 127.0.0.0/8 or ::1, any spelling. The peer's `::ffff:127.x.x.x` form is already reduced to the dotted quad. */
    private static function isLoopback(string $ip): bool
    {
        if (!str_contains($ip, ':')) {
            $n = IpParse::ip4($ip);
            return $n >= 0 && ($n >> 24) === 127;
        }
        return IpParse::ip6($ip) === [0, 0, 0, 1];
    }

    private static function validIp(string $s): bool
    {
        return !str_contains($s, ':') ? IpParse::ip4($s) >= 0 : IpParse::ip6($s) !== null;
    }

    /** @return Cidr|null */
    private static function parseCidr(string $c): ?array
    {
        $slash = strpos($c, '/');
        if ($slash === false) {
            return null;
        }
        $addr = substr($c, 0, $slash);
        $bitsRaw = substr($c, $slash + 1);
        if (preg_match('/^\d+$/', $bitsRaw) !== 1) {
            return null;
        }
        $bits = (int) $bitsRaw;
        if (!str_contains($addr, ':')) {
            $base = IpParse::ip4($addr);
            return $base >= 0 && $bits <= 32 ? ['base4' => $base, 'base6' => null, 'bits' => $bits] : null;
        }
        $words = IpParse::ip6($addr);
        return $words !== null && $bits <= 128 ? ['base4' => -1, 'base6' => $words, 'bits' => $bits] : null;
    }

    /** @param Cidr $cidr */
    private static function inCidr(string $ip, array $cidr): bool
    {
        if ($cidr['base6'] === null) {
            $n = IpParse::ip4($ip);
            if ($n < 0) {
                return false;
            }
            $bits = $cidr['bits'];
            $mask = $bits === 0 ? 0 : (0xFFFFFFFF << (32 - $bits)) & 0xFFFFFFFF;
            return ($n & $mask) === ($cidr['base4'] & $mask);
        }
        $words = IpParse::ip6($ip);
        if ($words === null) {
            return false;
        }
        $remaining = $cidr['bits'];
        for ($k = 0; $k < 4 && $remaining > 0; $k++) {
            $take = min(32, $remaining);
            $mask = $take === 32 ? 0xFFFFFFFF : (0xFFFFFFFF << (32 - $take)) & 0xFFFFFFFF;
            if (($words[$k] & $mask) !== ($cidr['base6'][$k] & $mask)) {
                return false;
            }
            $remaining -= $take;
        }
        return true;
    }
}
