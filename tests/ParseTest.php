<?php

declare(strict_types=1);

namespace Camada\Tests;

use Camada\Snapshot\FileWords;
use Camada\Snapshot\Matcher;
use Camada\Snapshot\MatchInput;
use Camada\Snapshot\MemoryWords;
use Camada\Snapshot\Parser;
use Camada\Snapshot\Path;
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

    public function testEngineFailureFailsClosedForDenyRules(): void
    {
        $oldLimit = ini_get('pcre.backtrack_limit');
        $oldJit = ini_get('pcre.jit');
        ini_set('pcre.jit', '0');
        ini_set('pcre.backtrack_limit', '100');
        try {
            $ua = str_repeat('a', 40) . 'b';
            $rx = Regex::compile('^(a|aa)+$');
            self::assertFalse(@preg_match((string) $rx, $ua) !== false && preg_last_error() === PREG_NO_ERROR);   // the engine does fail here
            self::assertTrue(Regex::test($rx, $ua, true));
            self::assertFalse(Regex::test($rx, $ua));
            foreach (['ua' => new MatchInput(ua: $ua, path: '/x'), 'path' => new MatchInput(path: '/' . $ua)] as $f => $in) {
                $v = $f === 'ua' ? '^(a|aa)+$' : '^/(a|aa)+$';
                $deny = self::rulesSnapshot([['id' => 'd', 'action' => 'block', 'conds' => [['f' => $f, 'op' => 'matches', 'v' => $v]]]]);
                self::assertSame('d', $deny->match($in)->rule, $f);
                $skip = self::rulesSnapshot([
                    ['id' => 's', 'action' => 'skip', 'conds' => [['f' => $f, 'op' => 'matches', 'v' => $v]]],
                    ['id' => 'd', 'action' => 'block', 'conds' => [['f' => $f, 'op' => 'is', 'v' => $f === 'ua' ? $ua : '/' . $ua]]],
                ]);
                self::assertSame('d', $skip->match($in)->rule, $f . ' skip misses');
            }
        } finally {
            ini_set('pcre.backtrack_limit', (string) $oldLimit);
            ini_set('pcre.jit', (string) $oldJit);
        }
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
        $m2 = self::rulesSnapshot([['id' => 'any', 'action' => 'block', 'conds' => [['f' => 'ua', 'op' => 'matches', 'v' => '^a[^]b$']]]]);
        self::assertSame('any', $m2->match(new MatchInput(ua: 'a b'))->rule);
        self::assertNull($m2->match(new MatchInput(ua: 'ab'))->rule);
    }

    public function testJsIdentityEscapesAndDollarMatchJs(): void
    {
        $t = static fn (string $re, string $v): bool => Regex::test(Regex::compile($re), $v);
        self::assertFalse($t('^admin$', "admin\n"));
        self::assertTrue($t('^admin$', 'admin'));
        self::assertTrue(Regex::test(Regex::compile('^admin$', 'i'), 'ADMIN'));
        self::assertFalse(Regex::test(Regex::compile('^admin$', 'i'), "Admin\n"));
        self::assertNull(Regex::compile('^[\u0020-\u00FF]+$'));
        self::assertFalse($t('^[\u0020-\u00FF]+$', '日本'));
        self::assertNull(Regex::compile('[\u0080-\u00FF]'));
        self::assertFalse($t('[\u0080-\u00FF]', '日'));
        self::assertTrue($t('^\u007a$', 'z'));
        self::assertTrue($t('^z$', 'z'));
        foreach ([
            ['^\p{L}$', 'p{L}', true], ['^\p{L}$', 'A', false],
            ['^\x{41}$', 'A', false], ['^\x{2}$', 'xx', true],
            ['^\u{41}$', 'A', false], ['^\u{2}$', 'uu', true],
            ['^\o{101}$', 'A', false], ['^\o{2}$', 'oo', true],
            ['^\g{1}$', 'g', true], ['^\g{1}$', 'gg', false],
            ['^\Qa.b$', 'Qa.b', true], ['^\Qa.b$', 'Qaxb', true],
            ['^a{2}?$', '', false], ['^a{2}?$', 'aa', true],
            ['^\A\z$', 'Az', true], ['^\e$', 'e', true], ['^\h$', 'h', true],
            ['^\x4$', 'x4', true], ['\x4', 'x4', true], ['^\x41$', 'A', true], ['^A$', 'A', true],
            ['^\u0041$', 'A', true], ['^\u41$', 'u41', true],
            ['^\k$', 'k', true], ['(?<n>a)\k<n>', 'aa', true],
            ['^[\B]$', 'B', true], ['^[\p]$', 'p', true], ['^[\b]$', "\x08", true],
            ['^\d\w\s$', '1a ', true],
            ['^\c1$', '\c1', true], ['^\c$', '\c', true],
            ['^\v$', "\v", true], ['^\v$', "\n", false],
        ] as [$re, $v, $want]) {
            self::assertNotNull(Regex::compile($re), $re);
            self::assertSame($want, $t($re, $v), $re . ' ~ ' . $v);
        }
    }

    public function testJsDotEmptyClassAndWhitespaceMatchJs(): void
    {
        $t = static fn (string $re, string $v): bool => Regex::test(Regex::compile($re), $v);
        foreach ([
            ['^.$', "\r", false], ['^.$', "\n", false], ['^.$', "\u{2028}", false], ['^.$', "\u{2029}", false], ['^.$', 'a', true],
            ['^a.b$', "a\rb", false], ['^.*$', "a\u{2028}b", false], ['^[.]$', 'a', false], ['^\.$', '.', true],
            ['^[]a]$', 'a', false], ['^[]a]$', ']', false], ['^[]a]$', 'a]', false], ['[]a]', 'a]', false],
            ['^[^]x]$', 'qx]', true], ['a[]*b', 'ab', true], ['^a]$', 'a]', true],
            ['^\s$', "\u{00a0}", true], ['^\s$', "\u{2028}", true], ['^\s$', "\u{feff}", true], ['^\s$', "\x1c", false],
            ['^\S$', "\u{00a0}", false], ['^\S+$', 'ab', true], ['^\S+$', 'é', true], ['^\S+$', "a\u{00a0}", false],
            ['^[a\s]$', "\u{2028}", true], ['^[^a\s]$', "\u{00a0}", false], ['^[^a\s]$', 'b', true], ['^[^\S]$', "\u{00a0}", true],
            ['^[a-\sz]$', '-', true], ['^[a-\sz]$', 'm', false], ['^[a\s-z]$', 'm', false], ['^[\s^]$', '^', true], ['^[\s/]$', '/', true],
            ['^[\s-\cA-z]$', 'b', false], ['^[\s-\101-z]$', 'b', false], ['^[\s-\cA-z]$', '-', true],
            ['^[\s-a-z]$', 'b', false], ['^[\s-a-z]$', '-', true], ['^[\s-a-z]$', 'z', true], ['^[\s-\x41-z]$', 'b', false],
            ['^[\s-\d-z]$', 'b', false], ['^[\s-ab-z]$', 'c', true], ['^[a-\s-z]$', 'b', false], ['^[ \s]$', "\u{2003}", true],
            ['\S', "\u{a0}", false], ['\S', "\u{3000}", false], ['\S', "\u{feff}", false], ['\S', "\u{a0}\u{a0}\u{a0}", false], ['\S', "\u{a0}a", true],
            ['.', "\u{2028}", false], ['.', "\u{2029}", false], ['.', 'é', true], ['[^\s]', "\u{a0}", false], ['[^a\s]', "\u{a0}", false],
            ['[a\S]', "\u{a0}", false], ['^\S+$', "\u{a1}", true], ['(?<=.)x', "\u{2028}x", false], ['(?<=.)x', 'éx', true],
            ['\xA0', "\u{a0}", true], ['a\xA0', "a\u{a0}", true], ['^\xA0$', "\u{a0}", true], ['\xE9', 'é', true], ['\xA0', 'à', false],
            ['a|\S', "\u{a0}", false], ['', "\u{a0}", true], ['$', "\u{a0}", true],
        ] as [$re, $v, $want]) {
            self::assertNotNull(Regex::compile($re), $re);
            self::assertSame($want, $t($re, $v), $re . ' ~ ' . $v);
        }
    }

    public function testUnterminatedClassAfterSDashFailsOpenWithoutWarnings(): void
    {
        set_error_handler(static function (int $no, string $str): bool {   // an `@`-suppressed diagnostic is silent; anything else fails
            (error_reporting() & $no) === 0 || self::fail("PHP diagnostic: $str");
            return true;
        });
        try {
            self::assertNull(Regex::compile('[a\s-'));
            self::assertNull(Regex::compile('[\s-'));
        } finally {
            restore_error_handler();
        }
    }

    public function testOverlappingClassUnionDoesNotBacktrackExponentially(): void
    {
        self::assertFalse(Regex::test(Regex::compile('^[ \s]+x'), str_repeat(' ', 3000), true));
        self::assertSame(PREG_NO_ERROR, preg_last_error());
    }

    public function testDotAndNonSpaceSurviveLongInputs(): void
    {
        self::assertTrue(Regex::test(Regex::compile('^/admin/.*'), '/admin/' . str_repeat('a', 8200)));
        self::assertFalse(Regex::test(Regex::compile('^(.)*[xyz]$'), str_repeat('あ', 2048), true));
        self::assertTrue(Regex::test(Regex::compile('^\S*$'), str_repeat('あ', 4096), true));
        self::assertTrue(Regex::test(Regex::compile('^.*$'), str_repeat('é', 5000), true));
        foreach (['.{700}', '\S{370}', '[^\s]{450}', '^.{1,255}$'] as $re) {
            self::assertNotNull(Regex::compile($re), $re);
        }
        self::assertTrue(Regex::test(Regex::compile('.{256,}'), str_repeat('a', 300)));
    }

    public function testSpaceInsideALookbehindStaysFixedLength(): void
    {
        $t = static fn (string $re, string $v): bool => Regex::test(Regex::compile($re), $v);
        self::assertSame('/' . '(?<![\xC0-\xFF]|[\xE0-\xFF][\x80-\xBF]|[\xF0-\xFF][\x80-\xBF]{2})' . '(?:(?<=\s)a)/D', Regex::compile('(?<=\s)a'));
        self::assertTrue($t('(?<=\s)a', ' a'));
        self::assertTrue($t('(?<![a\s])b', 'cb'));
        self::assertFalse($t('(?<![a\s])b', ' b'));
        self::assertTrue($t('(?<name>\s)b', ' b'));
        self::assertTrue($t('(?<=x)\s(?<n>a)', "x\u{00a0}a"));   // outside the lookbehind, \s is still Unicode
    }

    public function testNonJsBraceIsTextNotABound(): void
    {
        $t = static fn (string $re, string $v): bool => Regex::test(Regex::compile('^' . $re . '$'), $v);
        self::assertTrue($t('a{,3}', 'a{,3}'));
        self::assertFalse($t('a{,3}', 'aa'));
        self::assertTrue($t('a{,}', 'a{,}'));
        self::assertFalse($t('a{,}', 'aaa'));
        self::assertTrue($t('a{1,3}', 'aaa'));
        self::assertTrue($t('[{,3}]', ','));
        self::assertTrue($t('\{,3}', '{,3}'));
        self::assertTrue($t('x{', 'x{'));
        self::assertTrue($t('[^]{,2}', 'z{,2}'));
        foreach (['a{ ,3}', 'a{1, 3}', 'a{1,3 }', 'a{ 1 }', 'a{ 1}'] as $re) {   // PCRE2 10.43+ reads these as bounds, JS as text
            self::assertTrue($t($re, $re), $re);
            self::assertFalse($t($re, 'a'), $re);
        }
        self::assertNull(Regex::compile('a{2,1}'));
        $m = self::rulesSnapshot([['id' => 'r', 'action' => 'block', 'conds' => [['f' => 'ua', 'op' => 'matches', 'v' => '.{,2000}.{,2000}.{,2000}!']]]]);
        $t0 = hrtime(true);
        $rule = $m->match(new MatchInput(ua: '!' . str_repeat('a', 2047), path: '/x'))->rule;
        self::assertNull($rule);
        self::assertLessThan(100_000_000, hrtime(true) - $t0);
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

    /** @return list<array<string, mixed>> */
    private static function mrule(string $id, string $action, string $f, ?string $name, string $rx): array
    {
        return [['id' => $id, 'action' => $action, 'conds' => [['f' => $f, 'op' => 'matches', 'v' => $rx] + ($name === null ? [] : ['name' => $name])]]];
    }

    public function testUnitsCountUtf16AndInvalidUtf8AsBytes(): void
    {
        self::assertSame(2048, Parser::units(str_repeat('é', 2048)));
        self::assertSame(2048, Parser::units(str_repeat("\u{1F600}", 1024)));
        self::assertSame(2050, Parser::units(str_repeat("\u{1F600}", 1025)));
        self::assertSame(3, Parser::units("a\xff\xfe"));
        self::assertSame(0, Parser::units(''));
        self::assertTrue(Parser::overCap(str_repeat("\xff", 2049)));
        self::assertFalse(Parser::overCap(str_repeat('é', 2048)));
    }

    public function testMatchesCapsInputFailingClosedForDenyAndMissForSkip(): void
    {
        $deny = self::rulesSnapshot([
            ...self::mrule('u', 'warn', 'ua', null, '(Scrapy|python-requests)/[0-9]'),
            ...self::mrule('h', 'challenge', 'header', 'x-v', '^1\.[0-2]\.'),
            ...self::mrule('p', 'block', 'path', null, '^/api/v[0-9]+/dump$'),
        ]);
        $ua = static fn (string $v) => $deny->match(new MatchInput(ua: $v))->rule;
        $hd = static fn (string $v) => $deny->match(new MatchInput(header: static fn (string $n): string => $v))->rule;
        $pa = static fn (string $v) => $deny->match(new MatchInput(path: $v))->rule;
        self::assertNull($ua(str_repeat('a', 2048)));
        self::assertSame('u', $ua(str_repeat('a', 2049)));
        self::assertNull($ua(str_repeat('é', 2048)));
        self::assertNull($ua(str_repeat("\u{1F600}", 1024)));
        self::assertSame('u', $ua(str_repeat("\u{1F600}", 1025)));
        // camada-all-wh9m: a deny reads the raw value too; raw 2049 is over the cap (v2 pinned a miss)
        self::assertSame('u', $ua('Mozilla/5.0 ' . str_repeat('a', 2036) . "\t"));
        self::assertSame('h', $hd(str_repeat('9', 2049)));
        self::assertNull($hd(str_repeat('9', 2048)));
        self::assertNull($pa('/x/' . str_repeat('a', 2045)));
        self::assertSame('p', $pa('/x/' . str_repeat('a', 2046)));
        self::assertSame('p', $pa('/' . str_repeat('%61', 700)));
        self::assertNull($pa('/x?' . str_repeat('q', 3000)));

        $skip = self::rulesSnapshot([
            ...self::mrule('s', 'skip', 'ua', null, '^uptime-probe/[0-9]'),
            ...self::mrule('sp', 'skip', 'path', null, '^/static-mirror/'),
            ...self::mrule('e', 'warn', 'ua', null, 'Scrapy'),
            ...self::mrule('c', 'block', 'path', null, '^/api/v[0-9]+/dump$'),
        ]);
        $up = 'uptime-probe/1 ';
        $sm = '/static-mirror/';
        self::assertSame('s', $skip->match(new MatchInput(ua: $up . str_repeat('a', 2033)))->rule);
        self::assertSame('e', $skip->match(new MatchInput(ua: $up . str_repeat('a', 2034)))->rule);
        self::assertSame('sp', $skip->match(new MatchInput(path: $sm . str_repeat('a', 2033)))->rule);
        self::assertSame('c', $skip->match(new MatchInput(path: $sm . str_repeat('a', 2034)))->rule);
        self::assertSame('sp', $skip->match(new MatchInput(path: $sm . str_repeat('%61', 700)))->rule);
        self::assertSame('c', $skip->match(new MatchInput(path: $sm . str_repeat('./', 1100) . 'x'))->rule);
    }

    public function testDenyReadsRawAndStrippedAndSkipNeverTakesAControlChar(): void
    {
        $m = self::rulesSnapshot([
            ...self::mrule('t', 'block', 'ua', null, 'a\tb'),
            ...self::mrule('q', 'block', 'ua', null, 'sqlmap'),
            ...self::mrule('ht', 'block', 'header', 'x-h', 'a\tb'),
            ...self::mrule('hq', 'block', 'header', 'x-q', 'sqlmap'),
        ]);
        self::assertSame('t', $m->match(new MatchInput(ua: "a\tb"))->rule);
        self::assertSame('q', $m->match(new MatchInput(ua: "sql\tmap"))->rule);
        self::assertNull($m->match(new MatchInput(ua: 'ab'))->rule);
        self::assertSame('ht', $m->match(new MatchInput(header: static fn (string $n): ?string => $n === 'x-h' ? "a\tb" : null))->rule);
        self::assertSame('hq', $m->match(new MatchInput(header: static fn (string $n): ?string => $n === 'x-q' ? "sql\tmap" : null))->rule);
        $s = self::rulesSnapshot([
            ...self::mrule('s', 'skip', 'ua', null, '^partner-[a-z]+$'),
            ...self::mrule('d', 'block', 'ua', null, 'partner'),
        ]);
        self::assertSame('s', $s->match(new MatchInput(ua: 'partner-acme'))->rule);
        self::assertSame('d', $s->match(new MatchInput(ua: "partner-acme\n"))->rule);
        $o = self::rulesSnapshot([
            ...self::mrule('s', 'skip', 'ua', null, '^a+$'),
            ...self::mrule('d', 'block', 'ua', null, '^zzz$'),
        ]);
        self::assertSame('d', $o->match(new MatchInput(ua: str_repeat('a', 2048) . "\t"))->rule);
        self::assertSame('s', $o->match(new MatchInput(ua: str_repeat('a', 2048)))->rule);
    }

    public function testControlCharsAreStrippedFromUaAndHeaderForMatchesOnly(): void
    {
        $m = self::rulesSnapshot([
            ...self::mrule('e', 'warn', 'ua', null, '(Scrapy|python-requests)/[0-9]'),
            ...self::mrule('s', 'skip', 'header', 'x-p', '^partner-[a-z]+$'),
            ['id' => 'k', 'action' => 'block', 'conds' => [['f' => 'ua', 'op' => 'contains', 'v' => 'curl/']]],
            ...self::mrule('c', 'block', 'path', null, '^/api/v[0-9]+/dump$'),
        ]);
        self::assertSame('e', $m->match(new MatchInput(ua: "python-requests\x00/2.32.0"))->rule);
        self::assertSame('e', $m->match(new MatchInput(ua: "Scrapy\t/2.11"))->rule);
        self::assertSame('e', $m->match(new MatchInput(ua: "python-requests/\x7f2"))->rule);
        self::assertNull($m->match(new MatchInput(ua: "cu\x00rl/8.4.0"))->rule);
        // a skip never exempts a value with a control char (v2 pinned 's')
        self::assertNull($m->match(new MatchInput(header: static fn (string $n): string => "partner-acme\n"))->rule);
        self::assertSame('s', $m->match(new MatchInput(header: static fn (string $n): string => 'partner-acme'))->rule);
        self::assertNull($m->match(new MatchInput(path: "/api/v2/dump\n"))->rule);
        self::assertNull($m->match(new MatchInput(path: '/api/v2/dump%0A'))->rule);
        self::assertSame('c', $m->match(new MatchInput(path: '/api/v2/dump'))->rule);
        self::assertSame(['/a%0a%7f', '/a%0a%7f', '/a%0a%7f'], Path::forms("/a\n\x7f"));
    }
}
