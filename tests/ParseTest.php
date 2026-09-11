<?php

declare(strict_types=1);

namespace Camada\Tests;

use Camada\Snapshot\FileWords;
use Camada\Snapshot\Matcher;
use Camada\Snapshot\MatchInput;
use Camada\Snapshot\MemoryWords;
use Camada\Snapshot\Parser;
use Camada\Snapshot\Regex;
use PHPUnit\Framework\TestCase;

/**
 * Container handling the golden cases do not reach: malformed input, the advisory version byte,
 * and the rule-compilation rules (drop, never guess).
 */
final class ParseTest extends TestCase
{
    /**
     * A tiny BLK container: header then the sections back to back.
     *
     * @param list<array{int, list<int>}> $sections
     */
    public static function container(int $magic, array $sections): string
    {
        $k = count($sections);
        $header = [$magic, $k];
        $off = 2 + $k * 3;
        $body = [];
        foreach ($sections as [$t, $words]) {
            array_push($header, $t, $off, count($words));
            array_push($body, ...$words);
            $off += count($words);
        }
        return pack('V*', ...$header, ...$body);
    }

    /** @return array<string, mixed> */
    private static function v4Meta(): array
    {
        return Fixtures::json('blk3/v4-basic.meta.json');
    }

    /**
     * @param list<array<string, mixed>> $rules
     * @param list<array{int, list<int>}> $sections
     */
    public static function rulesSnapshot(array $rules, array $sections = []): Matcher
    {
        return new Matcher(Parser::parse(new MemoryWords(self::container(0x424C4B35, $sections)), ['version' => 'v', 'rules' => $rules]));
    }

    public function testBadMagicAndTruncationThrow(): void
    {
        foreach (['nope', pack('V2', 0x424C4B35, 3), pack('V5', 0x424C4B35, 1, 10, 5, 100)] as $bad) {
            try {
                Parser::parse(new MemoryWords($bad), ['version' => '1']);
                self::fail('expected a parse failure');
            } catch (\RuntimeException $e) {
                self::assertStringContainsString('BLK', $e->getMessage());
            }
        }
    }

    public function testUnalignedTailIsDroppedNotFatal(): void
    {
        $snap = Parser::parse(new MemoryWords(Fixtures::bin('blk3/v4-basic.bin') . "\x01"), self::v4Meta());
        self::assertSame(4, $snap->format);
    }

    public function testFileAndMemoryInputsAgree(): void
    {
        $file = new Matcher(Parser::parse(FileWords::open(Fixtures::path('blk3/v4-basic.bin')), self::v4Meta()));
        $mem = new Matcher(Parser::parse(new MemoryWords(Fixtures::bin('blk3/v4-basic.bin')), self::v4Meta()));
        self::assertSame('ip4', $file->match(new MatchInput(ip: '203.0.113.66'))->reason);
        self::assertSame('ip4', $mem->match(new MatchInput(ip: '203.0.113.66'))->reason);
    }

    public function testAMissingFileFailsAtOpenNotAtMatch(): void
    {
        $this->expectException(\RuntimeException::class);
        FileWords::open(sys_get_temp_dir() . '/camada-no-such-file-' . getmypid() . '.bin');
    }

    public function testV3MagicStillReadsV4Sections(): void
    {
        // the version byte is advisory: an allow range under a BLK3 magic still allows
        $n = (192 << 24) | (0 << 16) | (2 << 8) | 20;
        $bin3 = self::container(0x424C4B33, [[10, [$n, $n]]]);
        $r = (new Matcher(Parser::parse(new MemoryWords($bin3), ['version' => 'x'])))->match(new MatchInput(ip: '192.0.2.20'));
        self::assertTrue($r->allowed);
        self::assertSame('ip4', $r->reason);
        self::assertSame(3, Parser::parse(new MemoryWords($bin3), ['version' => 'x'])->format);
    }

    public function testUnknownActionAndEmptyRulesAreDropped(): void
    {
        $m = self::rulesSnapshot([
            ['id' => 'a', 'action' => 'teleport', 'conds' => [['f' => 'path', 'op' => 'is', 'v' => '/x']]],
            ['id' => 'b', 'action' => 'block', 'conds' => []],
            ['id' => 'c', 'action' => 'block', 'conds' => [['f' => 'path', 'op' => 'is', 'v' => '/x']]],
        ]);
        self::assertSame(['c'], array_map(static fn ($r) => $r->id, $m->snap->rules));
        self::assertSame('c', $m->match(new MatchInput(path: '/x'))->rule);
    }

    public function testRegexPcreRejectsNeverMatchesAndNeverThrows(): void
    {
        $m = self::rulesSnapshot([['id' => 'bad', 'action' => 'block', 'conds' => [['f' => 'path', 'op' => 'matches', 'v' => '(?<=a']]]]);
        self::assertFalse($m->match(new MatchInput(path: '/a'))->block);
        $m2 = new Matcher(Parser::parse(new MemoryWords(self::container(0x424C4B35, [])), ['version' => 'v', 'pathsRegex' => ['(?<=a', '^/dump$']]));
        self::assertSame('path', $m2->match(new MatchInput(path: '/dump'))->reason);
        self::assertNull(Regex::compile('(?<=a'));
        self::assertNull(Regex::compile('a{2,1}'));
        self::assertFalse(Regex::test(null, 'anything'));
    }

    public function testDelimiterAndNonAsciiSpellingsInPatterns(): void
    {
        self::assertTrue(Regex::test(Regex::compile('^/api/v1/'), '/api/v1/x'));     // the delimiter is escaped, not fatal
        self::assertTrue(Regex::test(Regex::compile('^\/x$'), '/x'));                 // an already-escaped slash stays one
        self::assertTrue(Regex::test(Regex::compile('^\\\\/y$'), '\\/y'));            // a literal backslash then a slash
        self::assertTrue(Regex::test(Regex::compile('[/]'), '/'));                     // inside a class too
        self::assertTrue(Regex::test(Regex::compile("caf\xc3\xa9"), "caf\xc3\xa9"));   // bytes compare as bytes without the u flag
        self::assertFalse(Regex::test(Regex::compile('^\d$'), "\xd9\xa3"));            // \d is ASCII, as JS reads it
    }

    public function testAsnConditionsCompareAsStringsAndUnanswerableFieldsNeverFire(): void
    {
        $m = self::rulesSnapshot([
            ['id' => 'asn', 'action' => 'block', 'conds' => [['f' => 'asn', 'op' => 'is_in', 'v' => [14061, '7922']]]],
            ['id' => 'cc', 'action' => 'block', 'conds' => [['f' => 'country', 'op' => 'is_not', 'v' => 'US']]],
        ]);
        self::assertSame('asn', $m->match(new MatchInput(asn: 14061))->rule);
        self::assertSame('asn', $m->match(new MatchInput(asn: 7922))->rule);
        self::assertNull($m->match(new MatchInput(asn: 1))->rule);      // country unanswerable: is_not stays false
        self::assertSame('cc', $m->match(new MatchInput(country: 'BR'))->rule);
    }

    public function testHeaderGetterThatThrowsOrReturnsJunkReadsAsAbsent(): void
    {
        $m = self::rulesSnapshot([['id' => 'h', 'action' => 'block', 'conds' => [['f' => 'header', 'op' => 'is', 'name' => 'X-Api-Key', 'v' => 'k']]]]);
        $boom = static function (string $n): ?string {
            throw new \RuntimeException('app bug');
        };
        self::assertFalse($m->match(new MatchInput(header: $boom))->block);
        /** @phpstan-ignore argument.type */
        self::assertFalse($m->match(new MatchInput(header: static fn (string $n): mixed => $n === 'x-api-key' ? 42 : null))->block);
        self::assertSame('h', $m->match(new MatchInput(header: static fn (string $n): ?string => $n === 'x-api-key' ? 'k' : null))->rule);
    }

    public function testTwoIpConditionsConsumeTwoSectionPairsInOrder(): void
    {
        $a = (10 << 24) | 1;
        $b = (10 << 24) | 2;
        $m = self::rulesSnapshot(
            [['id' => 'r', 'action' => 'block', 'conds' => [['f' => 'ip', 'op' => 'is_in', 'set' => true], ['f' => 'ip', 'op' => 'not_in', 'set' => true]]]],
            [[14, [0, $a, $a]], [15, [0]], [14, [0, $b, $b]], [15, [0]]],
        );
        self::assertSame('r', $m->match(new MatchInput(ip: '10.0.0.1'))->rule);   // in the first, not in the second
        self::assertNull($m->match(new MatchInput(ip: '10.0.0.2'))->rule);        // not in the first
        self::assertNull($m->match(new MatchInput(path: '/'))->rule);              // no address: false for every op, negatives included
    }

    public function testJsRegexSpellingsAreTranslated(): void
    {
        $m = self::rulesSnapshot([['id' => 'ver', 'action' => 'block', 'conds' => [['f' => 'path', 'op' => 'matches', 'v' => '^/api/(?<ver>v\d+)/']]]]);
        self::assertSame('ver', $m->match(new MatchInput(path: '/api/v2/dump'))->rule);
        self::assertNull($m->match(new MatchInput(path: "/api/v\xd9\xa3/dump"))->rule);   // \d is ASCII, as JS reads it
        $m2 = self::rulesSnapshot([['id' => 'any', 'action' => 'block', 'conds' => [['f' => 'ua', 'op' => 'matches', 'v' => '^a[^]b\cJ$']]]]);
        self::assertSame('any', $m2->match(new MatchInput(ua: "a\nb\n"))->rule);
        self::assertNull($m2->match(new MatchInput(ua: 'ab'))->rule);
    }

    public function testOneMatcherServesInterleavedRequestsWithoutCrosstalk(): void
    {
        $a = (10 << 24) | 1;
        $m = self::rulesSnapshot(
            [['id' => 'r', 'action' => 'block', 'conds' => [['f' => 'header', 'op' => 'is', 'name' => 'x-a', 'v' => '1'], ['f' => 'ip', 'op' => 'is_in', 'set' => true]]]],
            [[14, [0, $a, $a]], [15, [0]]],
        );
        $header = static fn (string $n): string => '1';
        for ($i = 0; $i < 200; $i++) {
            self::assertTrue($m->match(new MatchInput(ip: '10.0.0.1', header: $header))->block);
            self::assertFalse($m->match(new MatchInput(ip: '10.0.0.2', header: $header))->block);
        }
    }

    public function testAMalformedRuleIsDroppedNotEnforced(): void
    {
        $m = self::rulesSnapshot([
            ['id' => 'x', 'action' => 'block', 'conds' => 'not-a-list'],
            ['id' => 'y', 'action' => 'block', 'conds' => [['f' => 'ua', 'op' => 'contains', 'v' => 'curl']]],
        ]);
        self::assertSame(['y'], array_map(static fn ($r) => $r->id, $m->snap->rules));
        self::assertSame('y', $m->match(new MatchInput(ua: 'curl/8'))->rule);
        self::assertNull($m->match(new MatchInput(ua: 'wget'))->rule);
    }
}
