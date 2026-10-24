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
 * never throws — and never surfaces a warning (fail open). A backreference to a group that may not have captured on
 * that pass reads empty in JS and fails in PCRE: a forward or self reference becomes `(?:)`, one to a group under a min-0
 * quantifier or negative lookaround or in an alternation branch becomes the conditional `(?(N)\N)` (see scanGroups). It
 * fails open when the group or an ancestor repeats (JS resets captures per iteration and refuses an empty one, PCRE keeps
 * the last capture or an empty one), or when the group sits inside a positive lookahead (JS rejects an empty optional iteration and
 * tries paths in another order, a lookahead keeps its first).
 * A `(?` or `(*` group JS lacks (`(?i:`, `(?i)`, `(?>`, `(?#`, `(*FAIL)`, ...) fails open: JS rejects it or V8 mis-evaluates it, and PCRE gives the engine answer, so no translation can match (camada-all-lsl8).
 * Group names are rewritten to ordinals (`n1`, `n2`, ...; one per distinct name) since JS accepts Unicode names and
 * PCRE without `u` neither those nor one past 32 chars.
 * JS matches a lookbehind right to left, so the same applies to a backreference inside a lookbehind or to a group
 * inside one, and a `\k<name>` naming no group (a SyntaxError in JS) does too.
 * Byte mode counts bytes: a non-ASCII char is 2-4 bytes here and one or two UTF-16 units in JS (two for an emoji), so
 * a pattern that counts characters around one (`.`, `[^a]`, `.{n}`, a backreference to a captured `.`) or puts one in
 * a class or before a quantifier (`é?`, `é+`, `[é]`) can disagree, and under `i` only ASCII folds (`é` does not match
 * `É`); `.*` and a bare non-ASCII literal agree (an accepted gap, camada-all-mx0s).
 */
final class Regex
{
    private const JS_ATOM = '/\G(?:\\\\(?:c[A-Za-z0-9_]|x[0-9a-fA-F]{2}|u[0-9a-fA-F]{4}|[0-3][0-7]{0,2}|[4-7][0-7]?|(?!c)[\s\S])|[\s\S])/';   // one class atom
    private const JS_ESCAPE = '/\G(?:[bdDfnrsStvwW]|x[0-9a-fA-F]{2}|u[0-9a-fA-F]{4})/';   // the letter escapes JS reads without `u`
    /** PCRE2 match-limit steps per run, set in the pattern so no host ini is touched (PREG_BACKTRACK_LIMIT_ERROR past it). */
    public const MATCH_LIMIT = 500000;
    /** Regex time one request's rule walk may spend; once spent, a run answers `$onFailure` unrun. */
    public const REQUEST_REGEX_BUDGET_MS = 100;
    private static ?int $budgetNs = null;   // left in the open walk; null when none is active
    private const JS_BRACE = '/\G\{([0-9]+)(?:(,)([0-9]*))?\}/';   // a JS {m}, {m,} or {m,n}
    private const JS_REF = '/\G\\\\(?:k<([^<>]+)>|([1-9][0-9]*))/';   // a backreference: \k<name> or \N
    private const NON_JS_GROUP = '/\G\((?:\*|\?(?![:=!<]))/';   // a (? or (* opening none of the JS forms (?: (?= (?! (?<
    private const JS_GROUP = '/\G\(\?<([^<>]*)>/';   // a named group's opener: a JS name holds no `<` or `>`
    private const OTHER_ID_START = '\x{1885}\x{1886}\x{2118}\x{212E}\x{309B}\x{309C}';   // ID_Start beyond \p{L}\p{Nl} (PCRE2 < 10.40 has no \p{ID_Start})
    private const JS_NAME = '/^(?!.*\x{2E2F})[\p{L}\p{Nl}$_' . self::OTHER_ID_START . '][\p{L}\p{Nl}\p{Mn}\p{Mc}\p{Nd}\p{Pc}$\x{200C}\x{200D}' . self::OTHER_ID_START
        . '\x{00B7}\x{0387}\x{1369}-\x{1371}\x{19DA}\x{30FB}\x{FF65}]*\z/u';   // a JS group name: ID_Start then ID_Continue, plus $ _ ZWNJ ZWJ; U+2E2F is \p{Lm} but not an ID char
    private const UTF8_CHAR = '[\x00-\x7F]|[\xC0-\xFF][\x80-\xBF]*';   // one UTF-8 char: an ASCII byte, or a lead byte and its continuations
    private const JS_ESC = '/\G\\\\(?:c[A-Za-z]|x[0-9a-fA-F]{2}|u[0-9a-fA-F]{4}|0[0-7]{0,2}|' . self::UTF8_CHAR . ')/';   // one escape, as long as JS reads it
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
        [$diverges, $marks, $names] = self::scanGroups($js);
        if ($diverges || ($body = self::translate($js, $marks, $names)) === null) {
            return null;
        }
        $p = '/(*LIMIT_MATCH=' . self::MATCH_LIMIT . ')' . $body . '/D' . $flags;
        if (@preg_match($p, '') !== false) {
            return $p;
        }
        $p = str_replace([self::IN_WS, self::IN_LS], '', $p);   // the guards triple each atom's size: a huge repeat keeps byte atoms rather than fail open
        return @preg_match($p, '') === false ? null : $p;
    }

    /** Runs `$walk` (one request's rule walk) under a fresh request regex budget, reset afterwards. */
    public static function withBudget(callable $walk): mixed
    {
        self::$budgetNs = self::REQUEST_REGEX_BUDGET_MS * 1_000_000;
        try {
            return $walk();
        } finally {
            self::$budgetNs = null;
        }
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
        if (self::$budgetNs !== null && self::$budgetNs <= 0) {
            return $onFailure;   // the request's regex time is spent: answer like an over-cap value
        }
        $t = hrtime(true);
        $r = @preg_match($compiled, $value);
        if (preg_last_error() === PREG_JIT_STACKLIMIT_ERROR) {   // the interpreter keeps its stack on the heap
            $r = @preg_match('/(*NO_JIT)' . substr($compiled, 1), $value);
        }
        if (self::$budgetNs !== null) {
            self::$budgetNs -= hrtime(true) - $t;
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

    /**
     * @param array<int, array{int, bool}> $marks  reference offset => [its end, true for a conditional, false for `(?:)`]
     * @param array<string, string> $names  group name => ordinal ASCII name
     */
    private static function translate(string $pattern, array $marks, array $names): ?string
    {
        $out = '';
        $n = strlen($pattern);
        $inClass = false;
        [$start, $neg, $pulled, $pullEnd, $soloEnd] = [0, false, [], -1, -1];   // the open class: its `[` offset in $out, negation, \s/\S pulled out, where the last one ended, where the atom after its dash ended
        $groups = [];   // open groups, true for a lookbehind: `\s` there stays native (WS is 1-3 bytes; PCRE2 < 10.43 wants a fixed length)
        for ($i = 0; $i < $n;) {
            $ch = $pattern[$i];
            if ($ch === '\\' && $i + 1 < $n) {
                $c = $pattern[$i + 1];
                if (!$inClass && isset($marks[$i])) {   // a reference to a group that may be unset reads empty in JS
                    [$end, $cond] = $marks[$i];
                    $ref = substr($pattern, $i, $end - $i);
                    $id = $c === 'k' ? '<' . $names[substr($ref, 3, -1)] . '>' : substr($ref, 1);
                    $ref = $c === 'k' ? '\\k' . $id : $ref;
                    $out .= $cond ? '(?(' . $id . ')' . $ref . ')' : '(?:)';
                    $i = $end;
                    continue;
                }
                if (!$inClass && $c === 'k' && $names !== [] && preg_match(self::JS_REF, $pattern, $m, 0, $i) === 1) {
                    $out .= '\\k<' . $names[$m[1]] . '>';
                    $i += strlen($m[0]);
                    continue;
                }
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
                    || ($c === 'B' && !$inClass) || ($c === 'k' && $names !== []) || ($c === 'c' && ctype_alpha($d));
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
                if (preg_match(self::NON_JS_GROUP, $pattern, $unused, 0, $i) === 1) {
                    return null;   // fail open: JS rejects it or V8 mis-evaluates it, PCRE gives it a meaning
                }
                if ($names !== [] && ($pattern[$i + 1] ?? '') === '?' && preg_match(self::JS_GROUP, $pattern, $m, 0, $i) === 1 && isset($names[$m[1]])) {
                    $out .= '(?<' . $names[$m[1]] . '>';
                    $groups[] = false;
                    $i += strlen($m[0]);
                    continue;
                }
                $groups[] = preg_match('/\G\(\?<[=!]/', $pattern, $unused, 0, $i) === 1;
            } elseif ($ch === ')') {
                array_pop($groups);
            } elseif ($ch === '{' && preg_match(self::JS_BRACE, $pattern, $q, 0, $i) === 1) {
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

    /** Does the text at $j open a min-0 quantifier (`?`, `*`, `{0}` `{0,}` `{0,m}`)? */
    private static function min0At(string $p, int $j): bool
    {
        return in_array($p[$j] ?? '', ['?', '*'], true) || (($p[$j] ?? '') === '{' && preg_match(self::JS_BRACE, $p, $b, 0, $j) === 1 && self::cmp($b[1], '0') === 0);
    }

    /**
     * @return array{bool, array<int, array{int, bool}>, array<string, string>} [the pattern must fail open, {reference offset =>
     * [its end, true for a conditional, false for `(?:)`]}, {group name => ordinal ASCII name}]: one escape- and class-aware walk
     * (a class opens at an unescaped `[`, `[` is literal inside, the first unescaped `]` closes it). JS reads a
     * reference to an unset group as empty. One whose group is still open at the reference (forward or self) is always empty: false. One whose group sits under a min-0 quantifier or a negative lookaround (itself or any ancestor), or lies in an
     * alternation branch (an ancestor or the top level has a `|`), may be unset: true, unless the group or an ancestor repeats
     * (JS resets captures per iteration and refuses an empty one, PCRE keeps them) or it sits inside a positive lookahead (JS rejects an empty
     * optional iteration and tries paths in another order, a lookahead keeps its first): fail open. A name that is no JS identifier fails open. Frames are
     * created in `(` order, so one forward pass gives each its inherited flags and every reference is classified in O(1).
     * A plain reference (group closed before it) also fails open when the group or an ancestor that closes before the reference
     * repeats and can match empty: JS rejects an empty iteration once the minimum is met and keeps the previous capture, PCRE
     * takes it and overwrites the capture with ''. The same walk tracks per frame whether the current alternation branch holds
     * an atom that must consume input (`solid`: a literal, `.`, a class or a letter escape not followed by a min-0 quantifier,
     * or a non-nullable group) and whether the body can match empty (`nullable`: a branch without one, or a lookaround). Anything
     * unsure counts as nullable, which only fails open; a reference inside the repeating frame reads its own iteration's capture and stays.
     */
    private static function scanGroups(string $p): array
    {
        if (preg_match('/\\\\(?:[1-9]|k)|\(\?<[^=!]/', $p) !== 1) {
            return [false, [], []];
        }
        /** @var list<array{parent: int, alt: bool, min0: bool, neg: bool, lb: bool, end: int, rep: bool, la: bool, solid: bool, nullable: bool}> $frames  end is -1 while open */
        $frames = [['parent' => -1, 'alt' => false, 'min0' => false, 'neg' => false, 'lb' => false, 'end' => -1, 'rep' => false, 'la' => false, 'solid' => false, 'nullable' => false]];
        [$stack, $groups, $refs, $marks] = [[0], [], [], []];   // groups: [frame, name|null] in `(` order; refs: [name|number, is name, offset, end, frame]
        [$n, $inClass, $quiet] = [strlen($p), false, 0];   // bytes before $quiet (a group header, a `\k<name>`) are no atoms
        for ($i = 0; $i < $n;) {
            $ch = $p[$i];
            $top = $stack[count($stack) - 1];
            if ($ch === '\\') {
                if ($inClass) {
                    $i += 2;
                    continue;
                }
                if (preg_match(self::JS_REF, $p, $m, 0, $i) === 1) {
                    $refs[] = [$m[2] ?? $m[1], !isset($m[2]), $i, strlen($m[0]) + $i, $top];
                    if ($p[$i + 1] === 'k') {
                        $quiet = $i + strlen($m[0]);   // the name may hold structure chars the walk must still see
                        $i += 2;
                    } else {
                        $i += strlen($m[0]);
                    }
                    continue;
                }
                if (preg_match(self::JS_ESC, $p, $m, 0, $i) === 1) {
                    $j = $i + strlen($m[0]);
                    if (!in_array($m[0], ['\\b', '\\B', '\\c', '\\k'], true) && !self::min0At($p, $j)) {
                        $frames[$top]['solid'] = true;
                    }
                } else {
                    $j = $i + 2;
                }
                $i = $j;
                continue;
            }
            if ($inClass) {
                $inClass = $ch !== ']';
                if (!$inClass && !self::min0At($p, $i + 1)) {
                    $frames[$top]['solid'] = true;
                }
            } elseif ($ch === '[') {
                $inClass = true;
            } elseif ($ch === '(') {
                $q = ($p[$i + 1] ?? '') === '?';
                $cap = !$q || (($p[$i + 2] ?? '') === '<' && !in_array($p[$i + 3] ?? '', ['=', '!'], true));
                $gm = $q && $cap && preg_match(self::JS_GROUP, $p, $m, 0, $i) === 1 ? $m : null;
                $frames[] = ['parent' => $top, 'alt' => false, 'min0' => false, 'neg' => preg_match('/\G\?<?!/', $p, $unused, 0, $i + 1) === 1, 'lb' => preg_match('/\G\?<[=!]/', $p, $unused, 0, $i + 1) === 1, 'end' => -1, 'rep' => false, 'la' => preg_match('/\G\?=/', $p, $unused, 0, $i + 1) === 1, 'solid' => false, 'nullable' => false];
                $stack[] = count($frames) - 1;
                if ($gm !== null) {
                    $quiet = $i + strlen($gm[0]);
                } elseif ($q && $cap) {   // a name past `<` with a stray `<` or `>`: skip to the first `>`
                    $quiet = $i + 3 + strcspn($p, '<>', $i + 3) + 1;   // bounded to the header: a scan to the end is quadratic on long runs
                } else {
                    $quiet = $i + ($q ? (($p[$i + 2] ?? '') === '<' ? 4 : 3) : 1);
                    if ($q && !in_array($p[$i + 2] ?? '', [':', '=', '!', '<'], true)) {   // modifier flags `(?i:`: no atoms up to the `:`
                        $quiet = $i + 2 + strspn($p, 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ-', $i + 2);   // bounded to the flag run, no scan to the end
                        $quiet += ($p[$quiet] ?? '') === ':' ? 1 : 0;
                    }
                }
                if ($cap) {
                    $groups[] = [count($frames) - 1, $q ? ($gm !== null ? $gm[1] : '') : null];
                }
            } elseif ($ch === '|') {
                $frames[$top]['alt'] = true;
                $frames[$top]['nullable'] = $frames[$top]['nullable'] || !$frames[$top]['solid'];
                $frames[$top]['solid'] = false;
            } elseif ($ch === ')' && count($stack) > 1) {
                $f = array_pop($stack);
                $isB = preg_match(self::JS_BRACE, $p, $b, 0, $i + 1) === 1;
                $min0 = self::min0At($p, $i + 1);
                $rep = in_array($p[$i + 1] ?? '', ['+', '*'], true)
                    || ($isB && (($b[2] ?? '') !== '' && ($b[3] ?? '') === '' || self::cmp(($b[3] ?? '') === '' ? $b[1] : $b[3], '1') > 0));   // {n,} {n} n>1 {n,m} m>1
                $fr = $frames[$f];
                $nullable = $fr['nullable'] || !$fr['solid'] || $fr['neg'] || $fr['lb'] || $fr['la'];
                $frames[$f] = ['end' => $i, 'min0' => $min0, 'rep' => $rep, 'nullable' => $nullable] + $fr;
                if (!$nullable && !$min0) {
                    $frames[$fr['parent']]['solid'] = true;
                }
            } elseif (!in_array($ch, ['^', '$', ')', '?', '*', '+'], true) && $i >= $quiet) {
                if ($ch === '{' && preg_match(self::JS_BRACE, $p, $b, 0, $i) === 1) {   // a quantifier, no atom
                    $i += strlen($b[0]);
                    continue;
                }
                $i += preg_match('/\G(?:' . self::UTF8_CHAR . ')/', $p, $m, 0, $i) === 1 ? strlen($m[0]) - 1 : 0;   // one UTF-8 char is one atom
                if (!self::min0At($p, $i + 1)) {
                    $frames[$top]['solid'] = true;
                }
            }
            $i++;
        }
        $names = [];
        foreach ($groups as $k => [, $name]) {
            if ($name !== null) {
                $names[$name] ??= $k;
            }
        }
        $ord = [];
        foreach (array_keys($names) as $name) {
            if (preg_match(self::JS_NAME, (string) $name) !== 1) {
                return [true, [], []];   // not a JS identifier (a SyntaxError), or invalid UTF-8
            }
            $ord[$name] = 'n' . (count($ord) + 1);   // every name is mapped: none collides with another, PCRE's 32-char limit never binds
        }
        $inLb = $unset = $repAbove = $inLa = [false];   // per frame: a lookbehind at or above, may be unset, a strict ancestor repeats, a positive lookahead at or above
        $rn = [-1];   // per frame: end of the innermost frame at or above it that repeats and can match empty, -1 if none
        foreach (array_slice($frames, 1) as $fr) {
            $par = $frames[$fr['parent']];
            $inLb[] = $fr['lb'] || $inLb[$fr['parent']];
            $unset[] = $fr['min0'] || $fr['neg'] || $par['alt'] || $unset[$fr['parent']];
            $repAbove[] = $par['rep'] || $repAbove[$fr['parent']];
            $inLa[] = $fr['la'] || $inLa[$fr['parent']];
            $rn[] = $fr['rep'] && $fr['nullable'] ? $fr['end'] : $rn[$fr['parent']];
        }
        foreach ($refs as [$ref, $isName, $at, $end, $rf]) {
            if ($isName && $names !== [] && !isset($names[$ref])) {
                return [true, [], []];   // JS: SyntaxError
            }
            $k = $isName ? $names[$ref] ?? null : (strlen($ref) < 8 && (int) $ref <= count($groups) ? (int) $ref - 1 : null);   // past the count it is an octal or identity escape
            if ($k === null) {
                continue;
            }
            $g = $groups[$k][0];
            if ($inLb[$rf] || $inLb[$g]) {   // JS reads a lookbehind right to left: "closed before the reference" flips
                return [true, [], []];
            }
            if ($frames[$g]['end'] < 0 || $frames[$g]['end'] > $at) {
                $marks[$at] = [$end, false];
            } elseif ($rn[$g] >= 0 && $rn[$g] < $at) {   // JS keeps the capture of an earlier iteration past an empty one, PCRE overwrites it
                return [true, [], []];
            } elseif ($unset[$g]) {
                if ($repAbove[$g] || $frames[$g]['rep'] || $inLa[$g]) {   // JS drops an empty iteration, captures included; PCRE keeps it
                    return [true, [], []];
                }
                $marks[$at] = [$end, true];
            }
        }
        return [false, $marks, $ord];
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
        return $out . (count($alts) > 1 ? '(?>' . implode('|', $alts) . ')' : implode('', $alts));
    }
}
