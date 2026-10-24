<?php

declare(strict_types=1);

namespace Camada\Snapshot;

/**
 * Tenant patterns are authored as JS regexes (the analyst validates them with `new RegExp`) and
 * read here by PCRE without the `u` flag, so \d \w \b stay ASCII as JS reads them. `(?<name>`
 * and `\cX` are native; `[^]` (any char) becomes `[\s\S]`; a `{` that is no JS quantifier
 * (`{,3}`, `{ 1}`) becomes `\{` (JS reads it as text, PCRE as a bound); the delimiter is escaped.
 * `$` ends the subject only (the `D` modifier: PCRE also matches it before a trailing newline, JS
 * does not). `\<letter>` outside JS's escape set is the bare letter, as JS reads it without `u`
 * (`\p{L}` is "p{L}", `\A` is "A"); ASCII `\u00HH` (below 0x80) becomes `\xHH` and `\v` becomes `\x0B`. At byte
 * level, as JS reads them: `.` excludes \n \r U+2028 U+2029 (DOT); `[]` never matches (`(?!)`, a `]` right after
 * `[`/`[^` closes the class, a stray `]` is text); `\s`/`\S` are JS's Unicode whitespace (WS/NWS), and inside a class
 * they become a union with the rest of it, a `-` beside one staying a literal dash. A pattern
 * PCRE still rejects never matches and never throws — and never surfaces a warning (fail open).
 */
final class Regex
{
    private const JS_ESCAPE = '/\G(?:[bdDfnrsStvwW]|x[0-9a-fA-F]{2}|u[0-9a-fA-F]{4})/';   // the letter escapes JS reads without `u`
    /** JS \s as UTF-8 bytes (PCRE's without `u` is ASCII); NWS is one byte that starts none of them. */
    private const WS = '(?:[\t-\r ]|\xC2\xA0|\xE1\x9A\x80|\xE2\x80[\x80-\x8A\xA8\xA9\xAF]|\xE2\x81\x9F|\xE3\x80\x80|\xEF\xBB\xBF)';
    private const NWS = '(?:(?!' . self::WS . ')[\s\S])';
    private const DOT = '(?:(?!\xE2\x80[\xA8\xA9])[^\n\r])';   // JS . (PCRE's excludes only \n)

    /** The delimited PCRE pattern, or null when this runtime rejects the spelling. `$flags` is 'i' for a path regex (§D3 "Path matching"). */
    public static function compile(string $js, string $flags = ''): ?string
    {
        $p = '/' . self::translate($js) . '/D' . $flags;
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
        [$start, $neg, $pulled, $pullEnd] = [0, false, [], -1];   // the open class: its `[` offset in $out, negation, \s/\S pulled out
        $named = preg_match('/\(\?<(?![=!])/', $pattern) === 1;
        for ($i = 0; $i < $n;) {
            $ch = $pattern[$i];
            if ($ch === '\\' && $i + 1 < $n) {
                $c = $pattern[$i + 1];
                if ($c === 's' || $c === 'S') {
                    $set = $c === 's' ? self::WS : self::NWS;
                    if ($inClass) {
                        [$pulled[], $pullEnd] = [$set, $i + 2];
                    } else {
                        $out .= $set;
                    }
                    $i += 2;
                    continue;
                }
                if (preg_match('/\Gu00([0-7][0-9a-fA-F])/', $pattern, $m, 0, $i + 1) === 1) {
                    $out .= '\\x' . $m[1];   // PCRE has no `\u`; only ASCII maps (no u flag: \x80+ is a byte), \u0080 and up stay `\u` and fail open
                    $i += 6;
                    continue;
                }
                $kept = !ctype_alpha($c) || preg_match(self::JS_ESCAPE, $pattern, $unused, 0, $i + 1) === 1
                    || ($c === 'B' && !$inClass) || ($c === 'k' && $named) || ($c === 'c' && ($inClass || ctype_alpha($pattern[$i + 2] ?? '')));
                $out .= match (true) {
                    $c === 'v' => '\\x0B',   // PCRE `\v` is any vertical space, JS only VT
                    $kept => '\\' . $c,     // `\/` and `\\` stay what they are
                    $c === 'c' => '\\\\c',  // JS reads `\c` before a non-letter as text
                    default => $c,          // JS without `u` reads `\e`, `\p`, `\A` as the letter
                };
                $i += 2;
                continue;
            }
            if ($ch === '/') {
                $out .= '\\/';
                $i++;
                continue;
            }
            if ($inClass) {
                if ($ch === ']' && $pulled !== []) {
                    $out = self::union($out, $start, $neg, $pulled);
                    [$inClass, $i] = [false, $i + 1];
                    continue;
                }
                $inClass = $ch !== ']';
                if ($ch === '-' && ($i === $pullEnd || preg_match('/\G-\\\\[sS]/', $pattern, $unused, 0, $i) === 1)) {
                    $ch = '\\-';   // JS reads `[a-\sz]` and `[a\s-z]` as a, -, whitespace, z
                }
            } elseif ($ch === '.' || $ch === ']') {
                $out .= $ch === '.' ? self::DOT : '\\]';
                $i++;
                continue;
            } elseif ($ch === '[') {
                $neg = ($pattern[$i + 1] ?? '') === '^';
                $j = $i + ($neg ? 2 : 1);
                if (($pattern[$j] ?? '') === ']') {
                    $out .= $neg ? '[\\s\\S]' : '(?!)';   // JS `[^]` is any char, `[]` never matches
                    $i = $j + 1;
                    continue;
                }
                [$start, $pulled, $inClass] = [strlen($out), [], true];
                $out .= substr($pattern, $i, $j - $i);
                $i = $j;
                continue;
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

    /** @param list<string> $pulled  Rebuild the class opened at $start as the union of its body and the \s/\S sets it held. */
    private static function union(string $out, int $start, bool $neg, array $pulled): string
    {
        $body = substr($out, $start + ($neg ? 2 : 1));
        $cls = $body === '' ? '' : '[' . ($body[0] === '^' ? '\\' : '') . $body . ']';   // `[\s^]` is not a negated class
        $alts = array_values(array_unique($pulled));
        $out = substr($out, 0, $start);
        if ($neg && in_array(self::NWS, $alts, true)) {   // `[^…\S]` is whitespace, a whole UTF-8 char, outside the body
            return $out . (in_array(self::WS, $alts, true) ? '(?!)' : ($cls === '' ? self::WS : "(?:(?!$cls)" . self::WS . ')'));
        }
        if ($cls !== '') {
            array_unshift($alts, $cls);
        }
        $u = implode('|', $alts);
        return $out . ($neg ? "(?:(?!$u)[\\s\\S])" : (count($alts) > 1 ? "(?:$u)" : $u));
    }
}
