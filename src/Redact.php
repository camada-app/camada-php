<?php

declare(strict_types=1);

namespace Camada;

/**
 * Redaction, non-configurable-off. The SDK never ships: Authorization/Cookie values (scheme
 * only, Events\Builder), body field values (shape only), query params that look like
 * credentials, or raw user identifiers (HMAC-hashed here, inside the SDK, before anything
 * reaches the spool). Ported from @camada/core src/redact.ts.
 */
final class Redact
{
    // Exact patterns of C6 v3, matched on decoded bytes (every pattern is ASCII, so a byte >= 0x80 never
    // matches). NAME_RE runs on ASCII-lowercased text (nameHit), so there is no case folding at all;
    // `\A`/`\z` are true string anchors (`$` would match before a trailing newline).
    private const NAME_RE = '/(pass(word)?|tok(en)?|secret|key|api[-_]?key|auth|sess(ion)?|sig(nature)?|code|jwt|bearer|credential)/';
    private const JWT_RE = '/\AeyJ[A-Za-z0-9_-]{6,}\.[A-Za-z0-9_-]{6,}/';
    private const HEX_RE = '/\A[a-fA-F0-9]{32,}\z/';
    private const B64_RE = '/\A[A-Za-z0-9+\/_-]{40,}={0,2}\z/';
    private const ESC_RE = '/%[0-9a-fA-F]{2}/';

    public const REDACT_ALLOWLIST = ['plan', 'role', 'locale', 'ab_variant'];   // additions only, never narrowing

    /**
     * Replaces credential-looking query parts with ~r, preserving structure and order (C6 v3). The
     * string is split on `&`, never URL-parsed. Each part's name and value are percent-decoded
     * (decode) before testing. `name=value` → `name=~r` when the name looks like a credential, the
     * value looks like one, or the value holds a nested query with a credential segment (replaced
     * whole, so payloads like `q=1' or '1'='1` stay visible to the scorer). A bare part (no `=`) →
     * `~r` when it looks like a credential value or holds a credential segment. Either half still
     * encoded after 4 decode passes counts as a credential. The output keeps the raw text.
     */
    public static function scrubQuery(?string $query): string
    {
        if ($query === null || strlen($query) <= 1) {
            return $query ?? '';
        }
        $lead = str_starts_with($query, '?') ? '?' : '';
        $out = [];
        foreach (explode('&', $lead !== '' ? substr($query, 1) : $query) as $p) {
            $eq = strpos($p, '=');
            if ($eq === false) {
                $d = self::decode($p);
                $out[] = $d === null || self::suspectValue($d) || self::nestedCred($d) ? '~r' : $p;
                continue;
            }
            $name = substr($p, 0, $eq);
            $dn = self::decode($name);
            $dv = self::decode(substr($p, $eq + 1));
            $out[] = $dn === null || $dv === null || self::nameHit($dn) || self::suspectValue($dv) || self::nestedCred($dv) ? "{$name}=~r" : $p;
        }
        return $lead . implode('&', $out);
    }

    /**
     * Percent-decoding that never throws: each `%HH` (ASCII hex) becomes that byte, any other `%`
     * stays, `+` stays. Up to 4 passes; text still holding a `%HH` after them is null (scrubbed).
     * Never urldecode/rawurldecode (`+` → space). Only ever used to TEST a part.
     */
    private static function decode(string $s): ?string
    {
        for ($i = 0; $i < 4 && preg_match(self::ESC_RE, $s) === 1; $i++) {
            $s = (string) preg_replace_callback(self::ESC_RE, static function (array $m): string {
                $b = hex2bin(substr($m[0], 1));   // two ASCII hex digits: always one byte
                return $b === false ? $m[0] : $b;
            }, $s);
        }
        return preg_match(self::ESC_RE, $s) === 1 ? null : $s;
    }

    /** Lowercase A-Z only, then a substring test: ASCII-only case folding by construction. */
    private static function nameHit(string $n): bool
    {
        return preg_match(self::NAME_RE, strtr($n, 'ABCDEFGHIJKLMNOPQRSTUVWXYZ', 'abcdefghijklmnopqrstuvwxyz')) === 1;
    }

    /** A decoded value carrying `?`, `&` or `=` is a credential when one of its `[?&]` segments is (no further decoding). */
    private static function nestedCred(string $d): bool
    {
        if (strpbrk($d, '?&=') === false) {
            return false;
        }
        foreach (preg_split('/[?&]/', $d) ?: [] as $seg) {
            $eq = strpos($seg, '=');
            if ($eq === false ? self::suspectValue($seg) : self::nameHit(substr($seg, 0, $eq)) || self::suspectValue(substr($seg, $eq + 1))) {
                return true;
            }
        }
        return false;
    }

    /**
     * A URL (a Referer) with its query and fragment run through scrubQuery (camada-all-ijsa); the
     * scheme, host and path are kept as they are. The path gets the same treatment as the request's
     * own path `p` (none): a same-origin Referer's path already shipped as `p` on that page's own
     * event, and a cross-origin one carries only the origin under the browsers' default policy.
     */
    public static function scrubUrl(?string $url): ?string
    {
        if ($url === null) {
            return null;
        }
        $hash = strpos($url, '#');
        $head = $hash === false ? $url : substr($url, 0, $hash);
        $q = strpos($head, '?');
        $scrubbed = $q === false ? $head : substr($head, 0, $q) . self::scrubQuery(substr($head, $q));
        return $hash === false ? $scrubbed : $scrubbed . '#' . self::scrubQuery(substr($url, $hash + 1));
    }

    private static function suspectValue(string $v): bool
    {
        return preg_match(self::JWT_RE, $v) === 1 || preg_match(self::HEX_RE, $v) === 1 || preg_match(self::B64_RE, $v) === 1;
    }

    /**
     * Body shape only: field names and byte sizes, never values. One level deep. Takes a decoded
     * JSON body; anything but an object (a list, a scalar) is null.
     *
     * @return array<string, int>|null
     */
    public static function bodyShape(mixed $obj): ?array
    {
        if (!is_array($obj) || ($obj !== [] && array_is_list($obj))) {
            return null;
        }
        $out = [];
        foreach ($obj as $k => $v) {
            if (is_string($v)) {
                $out[(string) $k] = strlen($v);
            } elseif ($v === null) {
                $out[(string) $k] = 0;
            } else {
                $enc = json_encode($v, JSON_UNESCAPED_SLASHES);
                $out[(string) $k] = $enc === false ? 0 : strlen($enc);
            }
        }
        return $out;
    }

    /**
     * Stable per-tenant pseudonym: HMAC-SHA256 keyed by the ingest token, labelled so the hash
     * can never double as anything else, truncated to 32 hex chars. The raw identifier never leaves.
     */
    public static function hashUserId(string $userId, string $ingestToken): string
    {
        return substr(hash_hmac('sha256', 'uid:' . $userId, $ingestToken), 0, 32);
    }
}
