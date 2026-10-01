<?php

declare(strict_types=1);

namespace Camada\Snapshot;

/**
 * Path matching (contracts §D3 "Path matching"), ported byte for byte from edge-analyst
 * src/blocklist.js canonPath / pathForms / pathHit. A path rule must catch every spelling a
 * framework routes to the same handler, so both sides are canonicalised: query cut at ? or #;
 * %XX decoded when it is printable ASCII other than / and % (%2F is never a separator, decoding
 * is one pass); every other byte written as lower-case %xx; ASCII lower-cased; each segment cut
 * at its first ; (servlet path parameters); empty segments dropped (// and a trailing slash);
 * . and .. resolved — `full`. `lit` skips the dot step, for a router that hands /locked/../x to
 * the /locked handler unresolved. A deny (block, challenge, warn) matches when raw, lit or full
 * does; an exemption (allow side, skip) needs lit AND full. Rule values go through the same
 * function once, at parse.
 */
final class Path
{
    // already canonical: the common case skips the byte walk
    private const CANON = '#^(?:/(?!\.\.?(?:/|$))[a-z0-9\-._~!$&\'()*+,=:@]+)+$#';

    private static function stripQuery(?string $raw): string
    {
        $p = $raw === null || $raw === '' ? '/' : $raw;
        $n = strcspn($p, '?#');
        return $n === strlen($p) ? $p : substr($p, 0, $n);
    }

    public static function canon(?string $raw, bool $dots = true): string
    {
        $p = self::stripQuery($raw);
        if ($p === '/' || preg_match(self::CANON, $p) === 1) {
            return $p;
        }
        $s = '';
        $n = strlen($p);
        for ($i = 0; $i < $n; $i++) {
            $c = ord($p[$i]);
            if ($c === 37 && $i + 2 < $n && ctype_xdigit($p[$i + 1]) && ctype_xdigit($p[$i + 2])) {
                $c = (int) hexdec($p[$i + 1] . $p[$i + 2]);
                $i += 2;
                if ($c === 47) {
                    $s .= '%2f';
                    continue;
                }
            }
            if ($c < 0x21 || $c > 0x7e || $c === 37) {
                $s .= sprintf('%%%02x', $c);
                continue;
            }
            $s .= chr($c >= 65 && $c <= 90 ? $c + 32 : $c);
        }
        $out = [];
        foreach (explode('/', $s) as $seg) {
            $k = strpos($seg, ';');
            if ($k !== false) {
                $seg = substr($seg, 0, $k);
            }
            if ($seg === '' || ($dots && $seg === '.')) {
                continue;
            }
            if ($dots && $seg === '..') {
                array_pop($out);
                continue;
            }
            $out[] = $seg;
        }
        return '/' . implode('/', $out);
    }

    /**
     * [raw (query cut), lit, full] for one request path.
     *
     * @return array{string, string, string}
     */
    public static function forms(?string $raw): array
    {
        $p = self::stripQuery($raw);
        if ($p === '/' || preg_match(self::CANON, $p) === 1) {
            return [$p, $p, $p];
        }
        return [$p, self::canon($p, false), self::canon($p, true)];
    }

    public static function dir(string $p): string
    {
        return str_ends_with($p, '/') ? $p : $p . '/';
    }

    /** A prefix entry or a starts_with value ending in / -> its canonical directory key ('/' stays '/'). */
    public static function dirKey(string $v): string
    {
        return self::dir(self::canon($v));
    }

    /**
     * Walks '/' boundaries: /a/b tries /, /a/, /a/b/.
     *
     * @param array<string, true> $prefixes
     */
    public static function prefixed(array $prefixes, string $path): bool
    {
        $d = self::dir($path);
        for ($i = 0; $i !== false; $i = strpos($d, '/', $i + 1)) {
            if (isset($prefixes[substr($d, 0, $i + 1)])) {
                return true;
            }
        }
        return false;
    }

    /**
     * Does `pred` hold for this request's path? deny = any spelling; exemption = both canonical forms.
     *
     * @param \Closure(string): bool $pred
     * @param array{string, string, string} $forms
     */
    public static function hit(\Closure $pred, array $forms, bool $deny): bool
    {
        return $deny
            ? $pred($forms[0]) || $pred($forms[1]) || $pred($forms[2])
            : $pred($forms[1]) && $pred($forms[2]);
    }

    /**
     * One path condition -> a predicate over a single path form.
     *
     * @param list<string> $values
     * @return \Closure(string): bool
     */
    public static function pred(string $op, array $values): \Closure
    {
        if ($op === 'matches') {
            $rx = Regex::compile($values[0] ?? '', 'i');
            return static fn (string $p): bool => Regex::test($rx, $p);
        }
        if ($op === 'starts_with') {
            $v = $values[0] ?? '';
            $key = str_ends_with($v, '/') ? self::dirKey($v) : self::canon($v);
            return static fn (string $p): bool => str_starts_with(self::dir($p), $key);
        }
        $set = [];
        foreach ($values as $v) {
            $set[self::canon($v)] = true;
        }
        return static fn (string $p): bool => isset($set[$p]);
    }
}
