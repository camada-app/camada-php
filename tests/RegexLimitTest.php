<?php

declare(strict_types=1);

namespace Camada\Tests;

use Camada\Snapshot\MatchInput;
use Camada\Snapshot\Parser;
use Camada\Snapshot\Regex;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/** Contract regex-limit v1 (camada-all-2pap): the PCRE match limit and the per-request regex budget. */
final class RegexLimitTest extends TestCase
{
    private const VECTORS = 'regex-limit/regex-limit-vectors.json';
    private const SHA256 = 'f74b088b497bffbdf716f16d160ca1757f38c8da49629d06e5f56f32a8aabc9b';

    /** @return array<string, mixed> */
    private static function vectors(): array
    {
        return Fixtures::json(self::VECTORS);
    }

    /** @return iterable<string, array{array<string, mixed>, bool}> */
    public static function rows(): iterable
    {
        foreach ([false, true] as $jit) {   // PHP caches a compiled pattern with the jit setting of its first use: nojit goes first
            foreach (self::overLimit() as $r) {
                yield $r['id'] . ($jit ? ' jit' : ' nojit') => [$r, $jit];
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
        $r = ParseTest::rulesSnapshot([$rule])->match(new MatchInput(
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
        self::assertSame($c['MAX_MATCH_INPUT'], Parser::MAX_MATCH_INPUT);
        self::assertFalse(Parser::overCap(str_repeat('a', $c['MAX_MATCH_INPUT'])));
        self::assertTrue(Parser::overCap(str_repeat('a', $c['MAX_MATCH_INPUT'] + 1)));
    }

    public function testCompileCarriesTheLimit(): void
    {
        self::assertStringStartsWith('/(*LIMIT_MATCH=500000)', (string) Regex::compile('a'));
    }

    /** @param array{id: string, rule: array<string, mixed>, input: array<string, mixed>, hit: array<string, bool>} $r */
    #[DataProvider('rows')]
    public function testOverLimitRowsAnswerLikeOverCap(array $r, bool $jit): void
    {
        $old = ini_get('pcre.jit');
        ini_set('pcre.jit', $jit ? '1' : '0');
        try {
            $t = hrtime(true);
            self::assertSame($r['hit']['budget'], self::hits($r['rule'], $r['input']), $r['id']);
            self::assertLessThan(2_000, (hrtime(true) - $t) / 1e6, $r['id'] . ' stopped at the limit');
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
        $this->assertNative('refused', 'native');
    }

    public function testAcceptedMatchRowsAnswerNative(): void
    {
        $this->assertNative('accepted_match', 'native');
    }

    public function testAstralSplitAnswersPerEngine(): void
    {
        $this->assertNative('astral_split', 'php');
    }

    private function assertNative(string $key, string $engine): void
    {
        $v = self::vectors();
        /** @var array<string, string> $base */
        $base = $v['refused_rule'];
        /** @var list<array{id: string, pattern: string, cases: list<array{ua: mixed, hit: array<string, bool>}>}> $rows */
        $rows = $v[$key];
        self::assertNotEmpty($rows);
        foreach ($rows as $row) {
            $rule = ['id' => $base['id'], 'action' => $base['action'], 'conds' => [['f' => $base['field'], 'op' => 'matches', 'v' => $row['pattern']]]];
            foreach ($row['cases'] as $c) {
                self::assertSame(
                    $c['hit'][$engine],
                    self::hits($rule, ['ip' => '8.8.8.8', 'ua' => $c['ua']]),
                    $row['id'] . ' ua=' . json_encode($c['ua'])
                );
            }
        }
    }

    public function testASpentRequestBudgetAnswersOnFailureWithoutRunning(): void
    {
        $hit = Regex::compile('^a');
        self::assertTrue(Regex::test($hit, 'a'));
        Regex::withBudget(static function () use ($hit): void {
            (new \ReflectionProperty(Regex::class, 'budgetNs'))->setValue(null, 0);   // the walk has spent its time
            self::assertTrue(Regex::test($hit, 'b', true), 'a spent budget fails a deny rule closed');
            self::assertFalse(Regex::test($hit, 'a'), 'a spent budget never exempts');
        });
        self::assertTrue(Regex::test($hit, 'a'), 'the budget is reset after the walk');
    }

    /** @return iterable<string, array{mixed, string, bool}> */
    public static function nonStringMatches(): iterable
    {
        foreach ([123, 0, true, null, ['x' => 1], ['^/a'], [123], ''] as $v) {
            foreach (['ua', 'path', 'header'] as $f) {
                foreach ([false, true] as $over) {
                    yield json_encode($v) . ' on ' . $f . ($over ? ' over the cap' : '') => [$v, $f, $over];
                }
            }
        }
    }

    /** camada-all-zpbv: a stored `matches` value that is '' or not a string never matches, over the cap or not. */
    #[DataProvider('nonStringMatches')]
    public function testANonStringMatchesValueNeverMatches(mixed $v, string $f, bool $over): void
    {
        $str = '123 0 1 true Array {"x"=>1} ["^/a"]';   // every coerced spelling of the values appears in the input
        $big = str_repeat('a', Parser::MAX_MATCH_INPUT + 1);
        $in = new MatchInput(
            ip: '8.8.8.8',
            path: $over && $f === 'path' ? "/a/$str/$big" : "/a/$str",
            ua: $over && $f === 'ua' ? "$str $big" : $str,
            header: static fn (string $n): string => $over && $f === 'header' ? "$str $big" : $str,
        );
        $cond = ['f' => $f, 'op' => 'matches', 'v' => $v] + ($f === 'header' ? ['name' => 'x-h'] : []);
        $blk = ['id' => 'cr_blk', 'action' => 'block', 'conds' => [['f' => 'ip', 'op' => 'is_not', 'v' => '1.1.1.1']]];
        self::assertFalse(ParseTest::rulesSnapshot([['id' => 'cr_b', 'action' => 'block', 'conds' => [$cond]]])->match($in)->block);
        $r = ParseTest::rulesSnapshot([['id' => 'cr_s', 'action' => 'skip', 'conds' => [$cond]], $blk])->match($in);
        self::assertSame('cr_blk', $r->rule);
    }
}
