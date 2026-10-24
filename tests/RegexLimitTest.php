<?php

declare(strict_types=1);

namespace Camada\Tests;

use Camada\Snapshot\Matcher;
use Camada\Snapshot\MatchInput;
use Camada\Snapshot\MemoryWords;
use Camada\Snapshot\Parser;
use Camada\Snapshot\Regex;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/** Contract regex-limit v1 (camada-all-2pap): the PCRE match limit and the per-request regex budget. */
final class RegexLimitTest extends TestCase
{
    private const VECTORS = 'regex-limit/regex-limit-vectors.json';
    private const SHA256 = '26a8c7bdac744186870cc41ed37f2a9c1673320d84bad403c2b1ee95fba92619';

    /** @return array<string, mixed> */
    private static function vectors(): array
    {
        return Fixtures::json(self::VECTORS);
    }

    /** @return iterable<string, array{string, bool}> */
    public static function rows(): iterable
    {
        /** @var list<array<string, mixed>> $rows */
        $rows = self::vectors()['over_limit'];
        foreach ([false, true] as $jit) {   // PHP caches a compiled pattern with the jit setting of its first use: nojit goes first
            foreach ($rows as $r) {
                yield $r['id'] . ($jit ? ' jit' : ' nojit') => [(string) $r['id'], $jit];
            }
        }
    }

    /** a string, or {prefix?, repeat, times, suffix?} */
    private static function expand(mixed $v): string
    {
        if (is_string($v)) {
            return $v;
        }
        /** @var array{prefix?: string, repeat: string, times: int, suffix?: string} $v */
        return ($v['prefix'] ?? '') . str_repeat($v['repeat'], $v['times']) . ($v['suffix'] ?? '');
    }

    /**
     * @param array<string, mixed> $rule
     * @param array<string, mixed> $input
     */
    private static function hits(array $rule, array $input): bool
    {
        $meta = Fixtures::json('blk5/v5-empty.meta.json');
        $meta['rules'] = [$rule];
        $m = new Matcher(Parser::parse(new MemoryWords(Fixtures::bin('blk5/v5-empty.bin')), $meta));
        $r = $m->match(new MatchInput(
            ip: isset($input['ip']) ? (string) $input['ip'] : null,
            path: isset($input['path']) ? self::expand($input['path']) : null,
            ua: isset($input['ua']) ? self::expand($input['ua']) : null,
        ));
        return $r->rule === $rule['id'];
    }

    public function testVectorsAreThePinnedFile(): void
    {
        self::assertSame(self::SHA256, hash_file('sha256', Fixtures::path(self::VECTORS)));
    }

    public function testConstantsMatchTheContract(): void
    {
        /** @var array<string, mixed> $c */
        $c = self::vectors()['constants'];
        self::assertSame($c['PHP_MATCH_LIMIT'], Regex::MATCH_LIMIT);
        self::assertSame($c['REQUEST_REGEX_BUDGET_MS'], Regex::REQUEST_REGEX_BUDGET_MS);
        self::assertSame($c['MAX_MATCH_INPUT'], 2048);
        self::assertFalse(Parser::overCap(str_repeat('a', $c['MAX_MATCH_INPUT'])));
        self::assertTrue(Parser::overCap(str_repeat('a', $c['MAX_MATCH_INPUT'] + 1)));
    }

    public function testCompileCarriesTheLimit(): void
    {
        self::assertStringStartsWith('/(*LIMIT_MATCH=500000)', (string) Regex::compile('a'));
    }

    #[DataProvider('rows')]
    public function testOverLimitRowsAnswerLikeOverCap(string $id, bool $jit): void
    {
        $old = ini_get('pcre.jit');
        ini_set('pcre.jit', $jit ? '1' : '0');
        try {
            foreach (self::overLimit() as $r) {
                if ($r['id'] !== $id) {
                    continue;
                }
                /** @var array<string, bool> $hit */
                $hit = $r['hit'];
                $t = hrtime(true);
                self::assertSame($hit['budget'], self::hits($r['rule'], $r['input']), $id);
                self::assertLessThan(2_000, (hrtime(true) - $t) / 1e6, "$id stopped at the limit");
            }
        } finally {
            ini_set('pcre.jit', (string) $old);
        }
    }

    /** @return list<array{id: string, rule: array<string, mixed>, input: array<string, mixed>, hit: array<string, bool>}> */
    private static function overLimit(): array
    {
        /** @var list<array{id: string, rule: array<string, mixed>, input: array<string, mixed>, hit: array<string, bool>}> $r */
        $r = self::vectors()['over_limit'];
        return $r;
    }

    public function testAHostBacktrackLimitDoesNotRaiseTheCeiling(): void
    {
        $old = ini_get('pcre.backtrack_limit');
        ini_set('pcre.backtrack_limit', '100000000');
        try {
            $r = self::overLimit()[0];
            $t = hrtime(true);
            self::assertTrue(self::hits($r['rule'], $r['input']));   // a deny rule hits: the run stopped
            self::assertLessThan(2_000, (hrtime(true) - $t) / 1e6);
        } finally {
            ini_set('pcre.backtrack_limit', (string) $old);
        }
    }

    public function testRefusedPatternsAnswerNative(): void
    {
        $v = self::vectors();
        /** @var array<string, string> $base */
        $base = $v['refused_rule'];
        /** @var list<array{id: string, pattern: string, cases: list<array{ua: mixed, hit: array<string, bool>}>}> $refused */
        $refused = $v['refused'];
        foreach ($refused as $row) {
            $rule = ['id' => $base['id'], 'action' => $base['action'], 'conds' => [['f' => $base['field'], 'op' => 'matches', 'v' => $row['pattern']]]];
            foreach ($row['cases'] as $c) {
                self::assertSame($c['hit']['native'], self::hits($rule, ['ip' => '8.8.8.8', 'ua' => $c['ua']]), $row['id']);
            }
        }
    }

    public function testASpentRequestBudgetAnswersOnFailureWithoutRunning(): void
    {
        $in = ['ip' => '8.8.8.8', 'ua' => 'a'];
        $deny = ['id' => 'cr_d', 'action' => 'block', 'conds' => [['f' => 'ua', 'op' => 'matches', 'v' => '^b']]];
        $skip = ['id' => 'cr_s', 'action' => 'skip', 'conds' => [['f' => 'ua', 'op' => 'matches', 'v' => '^a']]];
        self::assertFalse(self::hits($deny, $in));
        self::assertTrue(self::hits($skip, $in));
        Regex::$walkBudgetMs = 0;
        try {
            self::assertTrue(self::hits($deny, $in), 'a spent budget fails a deny rule closed');
            self::assertFalse(self::hits($skip, $in), 'a spent budget never exempts');
        } finally {
            Regex::$walkBudgetMs = Regex::REQUEST_REGEX_BUDGET_MS;
        }
        self::assertTrue(self::hits($skip, $in), 'the budget is reset after the walk');
        // outside a walk only the per-match limit applies
        self::assertTrue(Regex::test(Regex::compile('^a'), 'a'));
    }
}
