<?php

declare(strict_types=1);

namespace Camada\Snapshot;

/**
 * Tenant patterns are authored as JS regexes (the analyst validates them with `new RegExp`) and
 * read here by PCRE without the `u` flag, so \d \w \b stay ASCII as JS reads them. `(?<name>`
 * and `\cX` are native; `[^]` (any char) becomes `[\s\S]`; a `{` that is no JS quantifier
 * (`{,3}`, `{ 1}`) becomes `\{` (JS reads it as text, PCRE as a bound); the delimiter is escaped. A pattern
 * PCRE still rejects never matches and never throws — and never surfaces a warning (fail open).
 */
final class Regex
{
    /** The delimited PCRE pattern, or null when this runtime rejects the spelling. `$flags` is 'i' for a path regex (§D3 "Path matching"). */
    public static function compile(string $js, string $flags = ''): ?string
    {
        $p = '/' . self::translate($js) . '/' . $flags;
        return @preg_match($p, '') === false ? null : $p;
    }

    /**
     * `$onFailure` is what an engine failure answers (backtrack or JIT stack limit, bad UTF): a deny
     * rule passes true so a failure fails closed like an over-cap value; skip and the legacy list pass false.
     */
    public static function test(?string $compiled, string $value, bool $onFailure = false): bool
    {
        if ($compiled === null) {
            return false;
        }
        $r = @preg_match($compiled, $value);
        return $r === false || preg_last_error() !== PREG_NO_ERROR ? $onFailure : $r === 1;
    }

    private static function translate(string $pattern): string
    {
        $out = '';
        $n = strlen($pattern);
        $inClass = false;
        for ($i = 0; $i < $n;) {
            $ch = $pattern[$i];
            if ($ch === '\\' && $i + 1 < $n) {
                $out .= substr($pattern, $i, 2);   // an escape pair travels whole: `\/` and `\\` stay what they are
                $i += 2;
                continue;
            }
            if ($ch === '/') {
                $out .= '\\/';
                $i++;
                continue;
            }
            if ($inClass) {
                $inClass = $ch !== ']';
            } elseif ($ch === '[') {
                if (substr($pattern, $i, 3) === '[^]') {
                    $out .= '[\\s\\S]';
                    $i += 3;
                    continue;
                }
                $inClass = true;
            } elseif ($ch === '{' && preg_match('/\G\{[0-9]+(?:,[0-9]*)?\}/', $pattern, $unused, 0, $i) !== 1) {
                $out .= '\\{';
                $i++;
                continue;
            }
            $out .= $ch;
            $i++;
        }
        return $out;
    }
}
