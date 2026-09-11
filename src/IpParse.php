<?php

declare(strict_types=1);

namespace Camada;

/**
 * Allocation-free IP parsers, ported 1:1 from edge-analyst src/blocklist.js through
 * @camada/core src/snapshot/ipparse.ts (the reference the conformance fixtures are generated
 * from). Behaviour must not drift: ip4 returns -1 on anything unusual; ip6 rejects zone ids and
 * v4-mapped forms. PHP ints are 64-bit, so the words come back as a plain list of four.
 *
 * @phpstan-type Words array{int, int, int, int}
 */
final class IpParse
{
    /** Dotted-quad IPv4 to a uint32, or -1 when the string is not a plain IPv4 address. */
    public static function ip4(string $s): int
    {
        $n = $part = $digits = $dots = 0;
        $len = strlen($s);
        for ($i = 0; $i < $len; $i++) {
            $c = ord($s[$i]);
            if ($c === 46) {   // '.'
                if ($digits === 0 || $part > 255) {
                    return -1;
                }
                if (++$dots > 3) {
                    return -1;
                }
                $n = $n * 256 + $part;
                $part = $digits = 0;
            } elseif ($c >= 48 && $c <= 57) {
                $part = $part * 10 + ($c - 48);
                if (++$digits > 3) {
                    return -1;
                }
            } else {
                return -1;
            }
        }
        if ($dots !== 3 || $digits === 0 || $part > 255) {
            return -1;
        }
        return $n * 256 + $part;
    }

    /**
     * IPv6 text to four big-endian uint32 words, or null when it is not a plain IPv6 address.
     *
     * @return Words|null
     */
    public static function ip6(string $s): ?array
    {
        $length = strlen($s);
        $groups = [0, 0, 0, 0, 0, 0, 0, 0];
        $n = $val = $digits = 0;
        $dbl = -1;
        $i = 0;
        if ($length > 1 && $s[0] === ':' && $s[1] === ':') {
            $dbl = 0;
            $i = 2;
        }
        for (; $i <= $length; $i++) {
            $c = $i < $length ? $s[$i] : ':';   // a sentinel colon closes the last group
            if ($c === ':') {
                if ($digits > 0) {
                    if ($n >= 8) {
                        return null;
                    }
                    $groups[$n++] = $val;
                    $val = $digits = 0;
                } elseif ($i < $length) {
                    if ($dbl !== -1) {
                        return null;
                    }
                    $dbl = $n;
                }
            } else {
                $o = ord($c);
                if ($o >= 48 && $o <= 57) {
                    $d = $o - 48;
                } elseif ($o >= 97 && $o <= 102) {
                    $d = $o - 87;
                } elseif ($o >= 65 && $o <= 70) {
                    $d = $o - 55;
                } else {
                    return null;
                }
                $val = ($val << 4) | $d;
                if (++$digits > 4) {
                    return null;
                }
            }
        }
        if ($dbl === -1) {
            if ($n !== 8) {
                return null;
            }
        } else {
            if ($n >= 8) {
                return null;
            }
            $shift = 8 - $n;
            for ($k = 7; $k >= $dbl + $shift; $k--) {
                $groups[$k] = $groups[$k - $shift];
            }
            for ($k = $dbl; $k < $dbl + $shift; $k++) {
                $groups[$k] = 0;
            }
        }
        return [
            ($groups[0] << 16) | $groups[1],
            ($groups[2] << 16) | $groups[3],
            ($groups[4] << 16) | $groups[5],
            ($groups[6] << 16) | $groups[7],
        ];
    }
}
