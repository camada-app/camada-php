<?php

declare(strict_types=1);

namespace Camada\Snapshot;

use Camada\IpParse;

/**
 * Matcher: sub-millisecond checks over a parsed Snapshot, ported from @camada/core
 * src/snapshot/match.ts (itself from edge-analyst src/blocklist.js). Matching is fully
 * synchronous. The original's per-instance scratch request is not ported: the rule loop reads a
 * RuleRequest built per call, so one Matcher serves every request.
 *
 * Outcome order is contract (contracts §D3, fixtures pin it): the tenant's ordered custom rules
 * first (first match wins, the order IS the precedence), then allow -> block -> challenge.
 * Within each side the axis order is ip4 -> ip6 -> asn -> country -> tls -> path.
 * At the SDK position only ip, path, ua and the request headers are usually known;
 * asn/country/tlsx entries and conditions then simply never match — that is the documented,
 * honest enforcement scope (fail open, never guess).
 *
 * @phpstan-import-type Words from IpParse
 */
final class Matcher
{
    public function __construct(public readonly Snapshot $snap)
    {
    }

    public static function cleanPath(?string $raw): string
    {
        $p = $raw === null || $raw === '' ? '/' : $raw;
        $q = strpos($p, '?');
        return $q === false ? $p : substr($p, 0, $q);
    }

    /**
     * Binary search over interleaved [start, end] uint32 pairs sorted by start.
     *
     * @param list<int> $r
     */
    public static function inRange4(array $r, int $n): bool
    {
        $lo = 0;
        $hi = (count($r) >> 1) - 1;
        if ($hi < 0) {
            return false;
        }
        while ($lo < $hi) {
            $m = ($lo + $hi + 1) >> 1;
            if ($r[$m * 2] <= $n) {
                $lo = $m;
            } else {
                $hi = $m - 1;
            }
        }
        return $r[$lo * 2] <= $n && $n <= $r[$lo * 2 + 1];
    }

    /**
     * Compares the 4 words at a[o..o+3] against the address words.
     *
     * @param list<int> $a
     * @param Words $w
     */
    private static function cmpWords(array $a, int $o, array $w): int
    {
        for ($k = 0; $k < 4; $k++) {
            $x = $a[$o + $k];
            $y = $w[$k];
            if ($x !== $y) {
                return $x < $y ? -1 : 1;
            }
        }
        return 0;
    }

    /**
     * Binary search over an interleaved [4-word start, 4-word end] side section.
     *
     * @param list<int> $r
     * @param Words $w
     */
    public static function inRange6(array $r, int $n, array $w): bool
    {
        if ($n < 1) {
            return false;
        }
        $lo = 0;
        $hi = $n - 1;
        while ($lo < $hi) {
            $m = ($lo + $hi + 1) >> 1;
            if (self::cmpWords($r, $m * 8, $w) <= 0) {
                $lo = $m;
            } else {
                $hi = $m - 1;
            }
        }
        $o = $lo * 8;
        return self::cmpWords($r, $o, $w) <= 0 && self::cmpWords($r, $o + 4, $w) >= 0;
    }

    /**
     * Walks every '/'-terminated ancestor of `path`, the way the block side does.
     *
     * @param array<string, true> $prefixes
     */
    private static function prefixHit(array $prefixes, string $path): bool
    {
        $i = strpos($path, '/', 1);
        while ($i !== false) {
            if (isset($prefixes[substr($path, 0, $i + 1)])) {
                return true;
            }
            $i = strpos($path, '/', $i + 1);
        }
        return false;
    }

    private function blocked4(int $n): bool
    {
        $s = $this->snap;
        $b = $n >> 8;
        if ((($s->bm4->get($b >> 5) >> ($b & 31)) & 1) === 0) {
            return false;
        }
        $hi = $n >> 16;
        $left = $s->idx4->get($hi);
        $right = $s->idx4->get($hi + 1) - 1;
        if ($left > 0) {
            $left--;
        }
        if ($right < $left) {
            return false;
        }
        $s4 = $s->s4;
        while ($left < $right) {
            $m = ($left + $right + 1) >> 1;
            if ($s4->get($m) <= $n) {
                $left = $m;
            } else {
                $right = $m - 1;
            }
        }
        return $s4->get($left) <= $n && $n <= $s->e4->get($left);
    }

    /** @return Words */
    private static function words(Slice $s, int $o): array
    {
        return [$s->get($o), $s->get($o + 1), $s->get($o + 2), $s->get($o + 3)];
    }

    /**
     * @param Words $a
     * @param Words $b
     */
    private static function cmp(array $a, array $b): int
    {
        for ($k = 0; $k < 4; $k++) {
            if ($a[$k] !== $b[$k]) {
                return $a[$k] < $b[$k] ? -1 : 1;
            }
        }
        return 0;
    }

    /** @param Words $w */
    private function blocked6(array $w): bool
    {
        $s = $this->snap;
        $b = $w[0] >> 8;
        if ((($s->bm6->get($b >> 5) >> ($b & 31)) & 1) === 0) {
            return false;
        }
        $left = 0;
        $right = $s->n6 - 1;
        if ($right < 0) {
            return false;
        }
        $s6 = $s->s6;
        while ($left < $right) {
            $m = ($left + $right + 1) >> 1;
            if (self::cmp(self::words($s6, $m * 4), $w) <= 0) {
                $left = $m;
            } else {
                $right = $m - 1;
            }
        }
        $o = $left * 4;
        return self::cmp(self::words($s6, $o), $w) <= 0 && self::cmp($w, self::words($s->e6, $o)) <= 0;
    }

    private function blockedAsn(int $asn): bool
    {
        $s = $this->snap;
        if ($asn < 4194304) {
            return (($s->asnBm->get($asn >> 5) >> ($asn & 31)) & 1) !== 0;
        }
        $extra = $s->asnExtra;
        $left = 0;
        $right = $extra->length() - 1;
        while ($left <= $right) {
            $m = ($left + $right) >> 1;
            $v = $extra->get($m);
            if ($v === $asn) {
                return true;
            }
            if ($v < $asn) {
                $left = $m + 1;
            } else {
                $right = $m - 1;
            }
        }
        return false;
    }

    private function blockedPath(string $path): bool
    {
        $s = $this->snap;
        if (isset($s->pathsExact[$path])) {
            return true;
        }
        if ($s->pathsPrefix !== [] && self::prefixHit($s->pathsPrefix, $path)) {
            return true;
        }
        foreach ($s->pathsRegex as $rx) {
            if (Regex::test($rx, $path)) {
                return true;
            }
        }
        return false;
    }

    /**
     * The block side: v3 sections plus the top-level meta.
     *
     * @param Words|null $w
     */
    private function blockSide(MatchInput $i, int $n4, ?array $w): ?string
    {
        $s = $this->snap;
        if ($n4 >= 0 && $this->blocked4($n4)) {
            return 'ip4';
        }
        if ($w !== null && $this->blocked6($w)) {
            return 'ip6';
        }
        if ($i->asn !== null && $this->blockedAsn($i->asn)) {
            return 'asn';
        }
        if ($i->country !== null && $i->country !== '' && isset($s->country[$i->country])) {
            return 'country';
        }
        if ($i->tlsx !== null && $i->tlsx !== '' && isset($s->tls[$i->tlsx])) {
            return 'tls';
        }
        if (($s->pathsExact !== [] || $s->pathsPrefix !== [] || $s->pathsRegex !== []) && $this->blockedPath(self::cleanPath($i->path))) {
            return 'path';
        }
        return null;
    }

    /**
     * A v4 side list (allow or challenge). No tls axis: §A3's side meta has no tls key.
     *
     * @param Words|null $w
     */
    private static function side(RangeSet $st, MatchInput $i, int $n4, ?array $w): ?string
    {
        if ($st->empty) {
            return null;   // the common v3 snapshot
        }
        if ($n4 >= 0 && self::inRange4($st->r4, $n4)) {
            return 'ip4';
        }
        if ($w !== null && self::inRange6($st->r6, $st->n6(), $w)) {
            return 'ip6';
        }
        if ($i->asn !== null && isset($st->asn[$i->asn])) {
            return 'asn';
        }
        if ($i->country !== null && $i->country !== '' && isset($st->country[$i->country])) {
            return 'country';
        }
        if ($st->pathsExact !== [] || $st->pathsPrefix !== []) {
            $p = self::cleanPath($i->path);
            if (isset($st->pathsExact[$p])) {
                return 'path';
            }
            if ($st->pathsPrefix !== [] && self::prefixHit($st->pathsPrefix, $p)) {
                return 'path';
            }
        }
        return null;
    }

    /**
     * A rule decided this request (§D3): at most one of allowed / block / challenge / warn is
     * true, `reason` is 'rule', and `rule` names the id the adapters stamp on the event.
     */
    private static function ruleResult(CompiledRule $rule, string $version): MatchResult
    {
        $a = $rule->action;
        return new MatchResult(
            block: $a === 'block',
            challenge: $a === 'challenge',
            allowed: $a === 'skip',
            warn: $a === 'warn',
            action: $a,
            rule: $rule->id,
            reason: 'rule',
            version: $version,
        );
    }

    public function match(MatchInput $i): MatchResult
    {
        $s = $this->snap;
        $ip = $i->ip ?? '';
        $n4 = -1;
        $w = null;
        if ($ip !== '') {
            if (!str_contains($ip, ':')) {
                $n4 = IpParse::ip4($ip);
            } else {
                $w = IpParse::ip6($ip);
            }
        }
        if ($s->rules !== []) {
            $r = new RuleRequest(n4: $n4, ip6: $w, asn: $i->asn, country: $i->country, tlsx: $i->tlsx, path: self::cleanPath($i->path), ua: $i->ua, header: $i->header);
            foreach ($s->rules as $rule) {   // the order IS the precedence (§A4): first match wins
                foreach ($rule->conds as $cond) {
                    if (!$cond($r)) {
                        continue 2;
                    }
                }
                return self::ruleResult($rule, $s->version);
            }
        }
        $reason = self::side($s->allow, $i, $n4, $w);
        if ($reason !== null) {
            return new MatchResult(allowed: true, reason: $reason, version: $s->version);
        }
        $reason = $this->blockSide($i, $n4, $w);
        if ($reason !== null) {
            return new MatchResult(block: true, reason: $reason, version: $s->version);
        }
        $reason = self::side($s->challenge, $i, $n4, $w);
        if ($reason !== null) {
            return new MatchResult(challenge: true, reason: $reason, version: $s->version);
        }
        return new MatchResult(version: $s->version);
    }
}
