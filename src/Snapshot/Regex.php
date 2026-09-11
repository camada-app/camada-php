<?php

declare(strict_types=1);

namespace Camada\Snapshot;

/**
 * Tenant patterns are authored as JS regexes (the analyst validates them with `new RegExp`) and
 * read here by PCRE without the `u` flag, so \d \w \b stay ASCII as JS reads them. `(?<name>`
 * and `\cX` are native; `[^]` (any char) becomes `[\s\S]`; the delimiter is escaped. A pattern
 * PCRE still rejects never matches and never throws — and never surfaces a warning (fail open).
 */
final class Regex
{
    /** The delimited PCRE pattern, or null when this runtime rejects the spelling. */
    public static function compile(string $js): ?string
    {
        $p = '/' . self::translate($js) . '/';
        return @preg_match($p, '') === false ? null : $p;
    }

    public static function test(?string $compiled, string $value): bool
    {
        return $compiled !== null && @preg_match($compiled, $value) === 1;
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
            }
            $out .= $ch;
            $i++;
        }
        return $out;
    }
}
