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
     * @param TrustedProxy|null $cfg
     */
    public static function resolve(?string $peer, ?string $xff, ?array $cfg): ?string
    {
        $sock = $peer !== null && str_starts_with($peer, '::ffff:') ? substr($peer, 7) : $peer;   // dual-stack v4-mapped form
        if ($cfg === null || $cfg['mode'] === 'none' || $xff === null || $xff === '') {
            return $sock;
        }
        $entries = array_values(array_filter(array_map('trim', explode(',', $xff)), static fn (string $e): bool => $e !== ''));
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
            foreach (array_reverse($entries) as $entry) {
                $isTrusted = false;
                foreach ($trusted as $t) {
                    if (self::inCidr($entry, $t)) {
                        $isTrusted = true;
                        break;
                    }
                }
                if (!$isTrusted) {
                    $candidate = $entry;
                    break;
                }
            }
        }
        return $candidate !== null && self::validIp($candidate) ? $candidate : $sock;
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
