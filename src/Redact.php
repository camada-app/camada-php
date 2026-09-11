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
    private const NAME_RE = '/(pass(word)?|tok(en)?|secret|key|api[-_]?key|auth|sess(ion)?|sig(nature)?|code|jwt|bearer|credential)/i';
    private const JWT_RE = '/^eyJ[A-Za-z0-9_-]{6,}\.[A-Za-z0-9_-]{6,}/';
    private const HEX_RE = '/^[a-f0-9]{32,}$/i';
    private const B64_RE = '/^[A-Za-z0-9+\/_-]{40,}={0,2}$/';

    public const REDACT_ALLOWLIST = ['plan', 'role', 'locale', 'ab_variant'];   // additions only, never narrowing

    /** Replaces credential-looking query values with ~r, preserving structure and order. */
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
                $out[] = $p;
                continue;
            }
            $name = substr($p, 0, $eq);
            $value = substr($p, $eq + 1);
            $out[] = preg_match(self::NAME_RE, $name) === 1 || self::suspectValue($value) ? "{$name}=~r" : $p;
        }
        return $lead . implode('&', $out);
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
