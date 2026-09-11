<?php

declare(strict_types=1);

namespace Camada\Snapshot;

/**
 * BLK snapshot parser (v3, v4, v5), ported from @camada/core src/snapshot/parse.ts, itself a
 * port of edge-analyst src/blocklist.js load() (the reference implementation).
 *
 * Container: sectioned little-endian uint32 —
 *   [0] magic 0x424c4b3<version>   [1] section count K
 *   K x [type, offset(words), length(words)]   then the sections.
 * Types: 1 V4_STARTS  2 V4_ENDS  3 V4_IDX16  4 V4_BM24  5 V6_STARTS  6 V6_ENDS  7 V6_BM24
 *        8 ASN_BM  9 ASN_EXTRA.
 * v4 (contracts §A3) adds two side lists as INTERLEAVED range pairs:
 *        10 ALLOW_V4  11 ALLOW_V6  12 CHALLENGE_V4  13 CHALLENGE_V6
 *   *_V4: [start, end, …] (2 words per range, sorted by start)
 *   *_V6: [s0,s1,s2,s3, e0,e1,e2,e3, …] (8 words per range, big-endian word order, sorted by start)
 * v5 (contracts §D3) adds the tenant's ordered custom rules, which run BEFORE the three sides:
 *        14 RULE_V4  15 RULE_V6   — repeated, word 0 = the rule's index into meta.rules, then range
 *   pairs exactly as 10/11. One 14 + one 15 per `ip` condition, in condition order (an empty half
 *   still ships its index word), so a rule with two ip conditions reads two pairs.
 * Meta travels separately: { version, country[], tls[], pathsExact[], pathsPrefix[], pathsRegex[],
 *                            allow?: side, challenge?: side, rules?: [] } with side = { asn[], country[], pathsExact[], pathsPrefix[] }.
 * The version byte is advisory: sections 10-15 are read whenever they are present.
 *
 * Only the header (2 + 3K words) and the small sections (10-15) are read here; the big ones are
 * handed to the matcher as slices it seeks into per request.
 */
final class Parser
{
    private const FORMATS = [0x424C4B33 => 3, 0x424C4B34 => 4, 0x424C4B35 => 5];
    private const ACTIONS = ['skip' => true, 'block' => true, 'challenge' => true, 'warn' => true];

    /**
     * Parses a BLK container + meta into a Snapshot. Throws on a malformed container — callers
     * keep the previous snapshot, exactly like the edge collector does.
     *
     * @param array<string, mixed> $meta
     */
    public static function parse(WordSource $u, array $meta): Snapshot
    {
        $len = $u->length();
        $head = $u->range(0, 2);
        $fmt = count($head) === 2 ? (self::FORMATS[$head[0]] ?? null) : null;
        if ($fmt === null) {
            throw new \RuntimeException('camada: not a BLK3 snapshot');
        }
        $count = $head[1];
        if ($len < 2 + $count * 3) {
            throw new \RuntimeException('camada: truncated BLK3 header');
        }
        $table = $u->range(2, $count * 3);
        /** @var array<int, Slice> $sec */
        $sec = [];
        /** @var list<list<int>> $rule4 */
        $rule4 = [];
        /** @var list<list<int>> $rule6 */
        $rule6 = [];
        for ($i = 0; $i < $count; $i++) {
            [$t, $off, $ln] = [$table[$i * 3], $table[$i * 3 + 1], $table[$i * 3 + 2]];
            if ($off + $ln > $len) {
                throw new \RuntimeException('camada: truncated BLK3 section');
            }
            $s = new Slice($u, $off, $ln);
            if ($t === 14) {
                $rule4[] = $s->toArray();   // repeated, one per ip condition: kept in container order
            } elseif ($t === 15) {
                $rule6[] = $s->toArray();
            } else {
                $sec[$t] = $s;
            }
        }
        $s6 = $sec[5] ?? Slice::empty();
        return new Snapshot(
            version: (string) ($meta['version'] ?? ''),
            format: $fmt,
            s4: $sec[1] ?? Slice::empty(),
            e4: $sec[2] ?? Slice::empty(),
            idx4: $sec[3] ?? Slice::zeros(65537),
            bm4: $sec[4] ?? Slice::zeros(524288),
            s6: $s6,
            e6: $sec[6] ?? Slice::empty(),
            n6: intdiv($s6->length(), 4),
            bm6: $sec[7] ?? Slice::zeros(524288),
            asnBm: $sec[8] ?? Slice::zeros(131072),
            asnExtra: $sec[9] ?? Slice::empty(),
            country: self::set($meta['country'] ?? null),
            tls: self::set($meta['tls'] ?? null),
            pathsExact: self::set($meta['pathsExact'] ?? null),
            pathsPrefix: self::set($meta['pathsPrefix'] ?? null),
            pathsRegex: self::regexes($meta['pathsRegex'] ?? null),
            allow: self::rangeSet($sec[10] ?? null, $sec[11] ?? null, $meta['allow'] ?? null),
            challenge: self::rangeSet($sec[12] ?? null, $sec[13] ?? null, $meta['challenge'] ?? null),
            rules: self::compileRules($meta, $rule4, $rule6),
        );
    }

    /** @return array<string, true> */
    private static function set(mixed $list): array
    {
        $out = [];
        if (is_array($list)) {
            foreach ($list as $v) {
                if (is_scalar($v)) {
                    $out[(string) $v] = true;
                }
            }
        }
        return $out;
    }

    /** @return array<int, true> */
    private static function intSet(mixed $list): array
    {
        $out = [];
        if (is_array($list)) {
            foreach ($list as $v) {
                if (is_int($v) || (is_string($v) && is_numeric($v)) || is_float($v)) {
                    $out[(int) $v] = true;
                }
            }
        }
        return $out;
    }

    /** @return list<string> */
    private static function regexes(mixed $list): array
    {
        $out = [];
        if (is_array($list)) {
            foreach ($list as $p) {
                $rx = is_string($p) ? Regex::compile($p) : null;
                if ($rx !== null) {
                    $out[] = $rx;
                }
            }
        }
        return $out;
    }

    private static function rangeSet(?Slice $r4, ?Slice $r6, mixed $m): RangeSet
    {
        /** @var array<string, mixed> $m */
        $m = is_array($m) ? $m : [];
        return new RangeSet(
            r4: $r4 !== null ? $r4->toArray() : [],
            r6: $r6 !== null ? $r6->toArray() : [],
            asn: self::intSet($m['asn'] ?? null),
            country: self::set($m['country'] ?? null),
            pathsExact: self::set($m['pathsExact'] ?? null),
            pathsPrefix: self::set($m['pathsPrefix'] ?? null),
        );
    }

    // ---------- custom rules (v5) ----------

    /**
     * meta.rules + the repeated 14/15 sections -> predicates, in evaluation order. A rule this SDK
     * cannot compile (unknown action, no conditions) is dropped rather than guessed at.
     *
     * @param array<string, mixed> $meta
     * @param list<list<int>> $v4s
     * @param list<list<int>> $v6s
     * @return list<CompiledRule>
     */
    private static function compileRules(array $meta, array $v4s, array $v6s): array
    {
        $out = [];
        $rules = $meta['rules'] ?? null;
        if (!is_array($rules)) {
            return [];
        }
        foreach (array_values($rules) as $i => $r) {
            if (!is_array($r)) {
                continue;
            }
            $action = (string) ($r['action'] ?? '');
            if (!isset(self::ACTIONS[$action])) {
                continue;   // an action this SDK does not know: ignore the rule rather than guess
            }
            $v4 = array_values(array_filter($v4s, static fn (array $s): bool => ($s[0] ?? -1) === $i));
            $v6 = array_values(array_filter($v6s, static fn (array $s): bool => ($s[0] ?? -1) === $i));
            $sets = [];
            for ($k = 0, $n = max(count($v4), $count6 = count($v6)); $k < $n; $k++) {
                $sets[] = [$k < count($v4) ? array_slice($v4[$k], 1) : [], $k < $count6 ? array_slice($v6[$k], 1) : []];
            }
            $conds = [];
            try {
                $raw = $r['conds'] ?? null;
                if (!is_array($raw)) {
                    continue;   // a malformed rule is dropped, never enforced
                }
                foreach ($raw as $c) {
                    if (!is_array($c)) {
                        continue 2;
                    }
                    /** @var array<string, mixed> $c */
                    $conds[] = self::compileCond($c, $sets);
                }
            } catch (\Throwable) {
                continue;
            }
            if ($conds !== []) {   // a rule with no conditions would match everything
                $out[] = new CompiledRule((string) ($r['id'] ?? ''), $action, $conds);
            }
        }
        return $out;
    }

    /**
     * The string one condition reads, or null when this request cannot answer the field.
     * `header` is not here: it needs the condition's own name, so compileCond builds its reader.
     */
    private static function fieldValue(string $f, RuleRequest $r): ?string
    {
        return match ($f) {
            'asn' => $r->asn === null ? null : (string) $r->asn,
            'country' => $r->country !== null && $r->country !== '' ? $r->country : null,
            'tlsx' => $r->tlsx !== null && $r->tlsx !== '' ? $r->tlsx : null,
            'path' => $r->path,
            'ua' => $r->ua !== null && $r->ua !== '' ? $r->ua : null,
            default => null,   // an entity-plane field (bot.verified, rule): never true here
        };
    }

    /**
     * One condition -> a predicate. `sets` yields this rule's (v4, v6) section pair per ip
     * condition, in condition order, so an ip condition consumes the next one.
     *
     * @param array<string, mixed> $c
     * @param list<array{list<int>, list<int>}> $sets
     * @return \Closure(RuleRequest): bool
     */
    private static function compileCond(array $c, array &$sets): \Closure
    {
        $f = (string) ($c['f'] ?? '');
        $op = (string) ($c['op'] ?? '');
        $negate = $op === 'is_not' || $op === 'not_in';
        // A header condition reads the request through the caller's getter. The name is lower-cased
        // once, here; a tap that cannot read headers (no getter) and a header the request does not
        // carry are both null, and null is false for every op — the rule simply does not fire (fail
        // open, §A4). The getter is app code: one that throws, or answers something other than a
        // string, is read as "no header" rather than allowed to take the whole match() down.
        if ($f === 'header') {
            $hname = strtolower((string) ($c['name'] ?? ''));
            $read = static function (RuleRequest $r) use ($hname): ?string {
                if ($hname === '' || $r->header === null) {
                    return null;
                }
                try {
                    $v = ($r->header)($hname);
                } catch (\Throwable) {
                    return null;
                }
                return is_string($v) ? $v : null;
            };
        } else {
            $read = static fn (RuleRequest $r): ?string => self::fieldValue($f, $r);
        }
        if ($f === 'ip') {
            [$p4, $p6] = $sets !== [] ? array_shift($sets) : [[], []];
            $n6 = count($p6) >> 3;
            return static function (RuleRequest $r) use ($p4, $p6, $n6, $negate): bool {
                if ($r->n4 < 0 && $r->ip6 === null) {
                    return false;   // no address: false for every op, negatives included
                }
                $hit = ($r->n4 >= 0 && Matcher::inRange4($p4, $r->n4)) || ($r->ip6 !== null && Matcher::inRange6($p6, $n6, $r->ip6));
                return $negate ? !$hit : $hit;
            };
        }
        $raw = $c['v'] ?? null;
        $values = is_array($raw) ? array_map(static fn (mixed $x): string => is_scalar($x) ? (string) $x : '', array_values($raw)) : [is_scalar($raw) ? (string) $raw : ''];
        if ($op === 'matches') {
            $rx = Regex::compile($values[0] ?? '');
            return static function (RuleRequest $r) use ($read, $rx): bool {
                $v = $read($r);
                return $v !== null && Regex::test($rx, $v);
            };
        }
        if ($op === 'contains') {
            $needle = $values[0] ?? '';
            return static function (RuleRequest $r) use ($read, $needle): bool {
                $v = $read($r);
                return $v !== null && str_contains($v, $needle);
            };
        }
        if ($op === 'starts_with') {
            $prefix = $values[0] ?? '';
            return static function (RuleRequest $r) use ($read, $prefix): bool {
                $v = $read($r);
                return $v !== null && str_starts_with($v, $prefix);
            };
        }
        $members = array_fill_keys($values, true);   // is | is_not | is_in | not_in
        return static function (RuleRequest $r) use ($read, $members, $negate): bool {
            $v = $read($r);
            if ($v === null) {
                return false;
            }
            return $negate ? !isset($members[$v]) : isset($members[$v]);
        };
    }
}
