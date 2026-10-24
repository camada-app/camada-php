<?php

declare(strict_types=1);

namespace Camada\Snapshot;

/**
 * Tenant patterns are authored as JS regexes (the analyst validates them with `new RegExp`) and
 * read here by PCRE without the `u` flag, so \d \w \b stay ASCII as JS reads them. `(?<name>`
 * and `\cX` are native; `[^]` (any char) becomes `[\s\S]`; a `{` that is no JS quantifier
 * (`{,3}`, `{ 1}`) becomes `\{` (JS reads it as text, PCRE as a bound); the delimiter is escaped;
 * a quantifier bound above PCRE's 65535 is clamped (m to 65535; `{m,n}` with n above it becomes `{m,}`).
 * `$` ends the subject only (the `D` modifier: PCRE also matches it before a trailing newline, JS
 * does not). `\<letter>` outside JS's escape set is the bare letter, as JS reads it without `u`
 * (`\p{L}` is "p{L}", `\A` is "A"); `\u00HH`/`\xHH` below 0x80 become `\xHH` (0x80 and up fail open: JS reads U+00HH,
 * PCRE a byte); in a class `\c` before a digit or `_` is its control char, as JS reads it; `\v` becomes `\x0B`. At byte
 * level, as JS reads them: `.` excludes \n \r U+2028 U+2029 (DOT); `[]` never matches (`(?!)`, a `]` right after
 * `[`/`[^` closes the class, a stray `]` is text); `\s`/`\S` are JS's Unicode whitespace (WS/NWS), and inside a class
 * they become a union with the rest of it (atomic, WS first, so a char matches one way only: no ReDoS), a `-` beside one
 * staying a literal dash, as does a `-` right after the atom that follows it; a literal `[` in a class is escaped (no
 * POSIX classes, as in JS). An atom never starts inside a whitespace or line-terminator char (a lookbehind refuses its
 * continuation bytes; dropped when a huge repeat overflows PCRE). Inside a lookbehind `\s`/`\S` stay PCRE's ASCII ones
 * (WS is 1-3 bytes and PCRE2 < 10.43 needs a fixed-length lookbehind). A pattern PCRE still rejects never matches and
 * never throws — and never surfaces a warning (fail open).
 */
final class Regex
{
    private const JS_ATOM = '/\G(?:\\\\(?:c[A-Za-z0-9_]|x[0-9a-fA-F]{2}|u[0-9a-fA-F]{4}|[0-3][0-7]{0,2}|[4-7][0-7]?|(?!c)[\s\S])|[\s\S])/';   // one class atom
    private const JS_ESCAPE = '/\G(?:[bdDfnrsStvwW]|x[0-9a-fA-F]{2}|u[0-9a-fA-F]{4})/';   // the letter escapes JS reads without `u`
    private const MAX_REP = '65535';   // PCRE2's quantifier ceiling (JS has none)
    /** JS \s as UTF-8 bytes (PCRE's without `u` is ASCII); NWS is one byte that starts none of them. */
    private const WS = '(?:[\t-\r ]|\xC2\xA0|\xE1\x9A\x80|\xE2\x80[\x80-\x8A\xA8\xA9\xAF]|\xE2\x81\x9F|\xE3\x80\x80|\xEF\xBB\xBF)';
    private const LS = '\xE2\x80[\xA8\xA9]';
    private const IN_WS = '(?<!(?=' . self::WS . ')[\xC0-\xFF]|(?=' . self::WS . ')[\xE0-\xFF][\x80-\xBF])';   // refuses a byte strictly inside a WS char: one starts 1 byte back, or a 3-byte one 2 back
    private const IN_LS = '(?<!(?=' . self::LS . ')[\xC0-\xFF]|(?=' . self::LS . ')[\xE0-\xFF][\x80-\xBF])';   // the same for U+2028/9
    private const NWS = '(?:(?!' . self::WS . ')' . self::IN_WS . '[^\t-\r ])';   // one byte, unless a WS char starts here or covers it (an alternation per char overflows the JIT stack on `.*` at ~5 KB)
    private const DOT = '(?:(?!' . self::LS . ')' . self::IN_LS . '[^\n\r])';   // JS . (PCRE's excludes only \n)

    /** The delimited PCRE pattern, or null when this runtime rejects the spelling. `$flags` is 'i' for a path regex (§D3 "Path matching"). */
    public static function compile(string $js, string $flags = ''): ?string
    {
        $p = '/' . self::translate($js) . '/D' . $flags;
        if (@preg_match($p, '') !== false) {
            return $p;
        }
        $p = str_replace([self::IN_WS, self::IN_LS], '', $p);   // the guards triple each atom's size: a huge repeat keeps byte atoms rather than fail open
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
        if (preg_last_error() === PREG_JIT_STACKLIMIT_ERROR) {   // the interpreter keeps its stack on the heap
            $r = @preg_match('/(*NO_JIT)' . substr($compiled, 1), $value);
        }
        return $r === false || preg_last_error() !== PREG_NO_ERROR ? $onFailure : $r === 1;
    }

    /** Compares two digit strings numerically without (int) overflow. */
    private static function cmp(string $a, string $b): int
    {
        $a = ltrim($a, '0');
        $b = ltrim($b, '0');
        return strlen($a) <=> strlen($b) ?: strcmp($a, $b);
    }

    private static function translate(string $pattern): string
    {
        $out = '';
        $n = strlen($pattern);
        $inClass = false;
        [$start, $neg, $pulled, $pullEnd, $soloEnd] = [0, false, [], -1, -1];   // the open class: its `[` offset in $out, negation, \s/\S pulled out, where the last one ended, where the atom after its dash ended
        $groups = [];   // open groups, true for a lookbehind: `\s` there stays native (WS is 1-3 bytes; PCRE2 < 10.43 wants a fixed length)
        $named = preg_match('/\(\?<(?![=!])/', $pattern) === 1;
        for ($i = 0; $i < $n;) {
            $ch = $pattern[$i];
            if ($ch === '\\' && $i + 1 < $n) {
                $c = $pattern[$i + 1];
                if ($c === 's' || $c === 'S') {
                    $set = $c === 's' ? self::WS : self::NWS;
                    if (in_array(true, $groups, true)) {
                        $out .= '\\' . $c;
                        $pullEnd = $inClass ? $i + 2 : $pullEnd;
                    } elseif ($inClass) {
                        [$pulled[], $pullEnd] = [$set, $i + 2];
                    } else {
                        $out .= $set;
                    }
                    $i += 2;
                    continue;
                }
                if (preg_match('/\G(?:u00|x)([0-9a-fA-F]{2})/', $pattern, $m, 0, $i + 1) === 1) {
                    $out .= ($m[1][0] < '8' ? '\\x' : '\\u00') . $m[1];   // PCRE has no `\u`; only ASCII maps (no u flag: \x80+ is a byte, JS reads U+0080+), the rest stays `\u00HH` and fails open
                    $i += 1 + strlen($m[0]);
                    continue;
                }
                if (preg_match('/\G[23][0-7]{2}/', $pattern, $m, 0, $i + 1) === 1) {
                    $out .= sprintf('\\u%04X', octdec($m[0]));   // legacy octal \200-\377: JS reads U+0080-U+00FF, PCRE a byte; `\u` fails open
                    $i += 4;
                    continue;
                }
                $d = $pattern[$i + 2] ?? '';
                if ($inClass && $c === 'c' && (ctype_digit($d) || $d === '_')) {
                    $out .= sprintf('\\x%02X', ord($d) & 0x1F);   // JS Annex B: `[\c1]` is the control char, PCRE reads 'q'
                    $i += 3;
                    continue;
                }
                $kept = !ctype_alpha($c) || preg_match(self::JS_ESCAPE, $pattern, $unused, 0, $i + 1) === 1
                    || ($c === 'B' && !$inClass) || ($c === 'k' && $named) || ($c === 'c' && ctype_alpha($d));
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
                if ($ch === '-' && ($i === $pullEnd || $i === $soloEnd || preg_match('/\G-\\\\[sS]/', $pattern, $unused, 0, $i) === 1)) {
                    if ($i === $pullEnd) {   // JS reads the atom after that dash as standalone: a dash right after it is text too
                        // no atom when the pattern ends on the dash
                        $soloEnd = preg_match(self::JS_ATOM, $pattern, $m, 0, $i + 1) === 1 ? $i + 1 + strlen($m[0]) : strlen($pattern);
                    }
                    $ch = '\\-';   // JS reads `[a-\sz]` and `[a\s-z]` as a, -, whitespace, z
                }
                $ch = $ch === '[' ? '\\[' : $ch;   // JS has no POSIX classes: `[[:alpha:]]` is {[ : a l p h} then `]`
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
            } elseif ($ch === '(') {
                $groups[] = preg_match('/\G\(\?<[=!]/', $pattern, $unused, 0, $i) === 1;
            } elseif ($ch === ')') {
                array_pop($groups);
            } elseif ($ch === '{' && preg_match('/\G\{([0-9]+)(?:(,)([0-9]*))?\}/', $pattern, $q, 0, $i) === 1) {
                $i += strlen($q[0]);
                [$lo, $comma, $hi] = [$q[1], $q[2] ?? '', $q[3] ?? ''];
                if ($hi !== '' && self::cmp($lo, $hi) > 0) {
                    $out .= $q[0];   // m > n stays as written, which both engines reject
                    continue;
                }
                $lo = self::cmp($lo, self::MAX_REP) > 0 ? self::MAX_REP : $lo;
                $hi = self::cmp($hi, self::MAX_REP) > 0 ? '' : $hi;   // an upper bound past it never binds a real input
                $out .= '{' . $lo . $comma . $hi . '}';
                continue;
            } elseif ($ch === '{') {
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
        $alts = array_values(array_filter([   // WS first: a multibyte space goes whole
            in_array(self::WS, $alts, true) ? self::WS : '',
            $cls,
            in_array(self::NWS, $alts, true) ? self::NWS : '',
        ], static fn ($a) => $a !== ''));
        if ($neg) {
            return $out . '(?:(?!' . implode('|', $alts) . ')' . self::IN_WS . '[\\s\\S])';
        }
        return $out . (count($alts) > 1 ? '(?>' . implode('|', $alts) . ')' : $alts[0]);
    }
}
