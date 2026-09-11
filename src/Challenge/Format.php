<?php

declare(strict_types=1);

namespace Camada\Challenge;

/**
 * Wire constants and pure helpers for the SDK-served challenge (contracts §D2), ported from
 * @camada/core src/challenge/format.ts. Nothing here does crypto; Kit supplies HMAC and SHA-256
 * from ext/hash, so the format has exactly one definition across the family.
 */
final class Format
{
    public const CHALLENGE_COOKIE = '_cch';
    public const CHALLENGE_TTL_MS = 3_600_000;   // 1 h (contract)
    public const POW_BITS = 16;                  // leading zero bits of SHA-256("<nonce>.<solution>")
    public const NONCE_HEX = 32;                 // the nonce is the first 32 hex chars of the HMAC
    private const DAY_MS = 86_400_000;
    private const MAX_RETURN_TO = 2048;
    private const MAX_SOLUTION = 32;

    public static function utcDay(int $nowMs): int
    {
        return intdiv($nowMs, self::DAY_MS);
    }

    // Domain-separated messages: a nonce HMAC can never be replayed as a cookie HMAC.
    public static function nonceMessage(?string $ip, int $day): string
    {
        return 'camada-challenge-nonce|' . ($ip ?? '') . '|' . $day;
    }

    public static function tokenMessage(?string $ip, int $exp): string
    {
        return 'camada-challenge-token|' . ($ip ?? '') . '|' . $exp;
    }

    /** @return array{int, string}|null */
    public static function splitToken(?string $value): ?array
    {
        if ($value === null || $value === '') {
            return null;
        }
        $dot = strpos($value, '.');
        if ($dot === false || $dot === 0) {
            return null;
        }
        $expRaw = substr($value, 0, $dot);
        if (preg_match('/^-?\d+$/', $expRaw) !== 1) {
            return null;
        }
        $mac = substr($value, $dot + 1);
        return $mac !== '' ? [(int) $expRaw, $mac] : null;
    }

    /** Constant-time for equal-length strings; length itself is not a secret here. */
    public static function safeEqual(string $a, string $b): bool
    {
        return strlen($a) === strlen($b) && hash_equals($a, $b);
    }

    /** True when the hex digest starts with `bits` zero bits. */
    public static function powOk(string $hexDigest, int $bits = self::POW_BITS): bool
    {
        $nibbles = $bits >> 2;
        $rest = $bits & 3;
        if (strlen($hexDigest) < $nibbles + ($rest !== 0 ? 1 : 0)) {
            return false;
        }
        for ($i = 0; $i < $nibbles; $i++) {
            if ($hexDigest[$i] !== '0') {
                return false;
            }
        }
        if ($rest === 0) {
            return true;
        }
        $c = $hexDigest[$nibbles];
        if (!ctype_xdigit($c)) {
            return false;
        }
        return (hexdec($c) >> (4 - $rest)) === 0;
    }

    public static function solutionShapeOk(?string $solution): bool
    {
        return $solution !== null && $solution !== '' && strlen($solution) <= self::MAX_SOLUTION;
    }

    public static function challengeCookie(string $value, bool $secure): string
    {
        return self::CHALLENGE_COOKIE . '=' . $value . '; Path=/; Max-Age=' . intdiv(self::CHALLENGE_TTL_MS, 1000) . '; HttpOnly; SameSite=Lax' . ($secure ? '; Secure' : '');
    }

    /**
     * Only a printable-ASCII same-site absolute path survives: never an absolute URL, a
     * protocol-relative '//host' redirect, a control character, or something absurdly long.
     */
    public static function safeReturnTo(?string $raw): string
    {
        if ($raw === null || $raw === '' || strlen($raw) > self::MAX_RETURN_TO) {
            return '/';
        }
        if ($raw[0] !== '/' || (strlen($raw) > 1 && ($raw[1] === '/' || $raw[1] === '\\'))) {
            return '/';
        }
        if (preg_match('/^[\x21-\x7e]+$/', $raw) !== 1) {
            return '/';
        }
        return $raw;
    }

    /** A challenge page is only worth serving to a top-level HTML navigation (contract §D2). */
    public static function wantsHtml(?string $accept, ?string $secFetchDest): bool
    {
        if ($accept === null || !str_contains($accept, 'text/html')) {
            return false;
        }
        return $secFetchDest === null || $secFetchDest === '' || $secFetchDest === 'document';
    }

    public static function escapeAttr(string $s): string
    {
        return str_replace(['&', '<', '>', '"', "'"], ['&amp;', '&lt;', '&gt;', '&quot;', '&#39;'], $s);
    }

    /** Safe to drop inside an inline <script>: `<` is escaped so no value can close the element early. */
    public static function escapeScript(string $s): string
    {
        $json = json_encode($s, JSON_UNESCAPED_SLASHES | JSON_INVALID_UTF8_SUBSTITUTE);
        return str_replace('<', '\\u003c', $json === false ? '""' : $json);
    }

    /**
     * application/x-www-form-urlencoded, last value wins. Never throws on junk.
     *
     * @return array<string, string>
     */
    public static function parseFormBody(string $body): array
    {
        $out = [];
        foreach (explode('&', $body) as $pair) {
            if ($pair === '') {
                continue;
            }
            $eq = strpos($pair, '=');
            $k = $eq === false ? $pair : substr($pair, 0, $eq);
            $v = $eq === false ? '' : substr($pair, $eq + 1);
            $out[urldecode($k)] = urldecode($v);
        }
        return $out;
    }
}
