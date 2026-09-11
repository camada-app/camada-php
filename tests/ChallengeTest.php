<?php

declare(strict_types=1);

namespace Camada\Tests;

use Camada\Challenge\Format;
use Camada\Challenge\Kit;
use Camada\Challenge\Page;
use PHPUnit\Framework\TestCase;

/**
 * The SDK-served challenge (contracts §D2): a stateless per-(ip, UTC day) HMAC nonce, a 16-bit
 * SHA-256 proof of work, and an HMAC cookie bound to the ip for one hour. Ported case for case
 * from camada-core/test/challenge.test.ts.
 */
final class ChallengeTest extends TestCase
{
    private const DAY_MS = 86_400_000;
    private const NOW = 1_800_000_000_000;
    private const IP = '203.0.113.9';

    public static function solve(string $nonce, int $bits = 16): string
    {
        $n = 0;
        while (!Format::powOk(hash('sha256', "{$nonce}.{$n}"), $bits)) {
            $n++;
        }
        return (string) $n;
    }

    public function testNonceIsDeterministicPerIpAndUtcDay(): void
    {
        $kit = new Kit('secret');
        $a = $kit->nonce(self::IP, self::NOW);
        self::assertSame($a, $kit->nonce(self::IP, self::NOW + 1000));
        self::assertSame(Format::NONCE_HEX, strlen($a));
        self::assertMatchesRegularExpression('/^[0-9a-f]+$/', $a);
        self::assertNotSame($a, $kit->nonce('203.0.113.10', self::NOW));
        self::assertNotSame($a, $kit->nonce(self::IP, self::NOW + self::DAY_MS));
        self::assertNotSame($a, (new Kit('other'))->nonce(self::IP, self::NOW));
    }

    public function testNonceAcceptsTodayAndYesterdayRejectsOlderAndForgeries(): void
    {
        $kit = new Kit('secret');
        $yesterday = $kit->nonce(self::IP, self::NOW - self::DAY_MS);
        self::assertTrue($kit->nonceValid(self::IP, self::NOW, $kit->nonce(self::IP, self::NOW)));
        self::assertTrue($kit->nonceValid(self::IP, self::NOW, $yesterday));
        self::assertFalse($kit->nonceValid(self::IP, self::NOW, $kit->nonce(self::IP, self::NOW - 2 * self::DAY_MS)));
        self::assertFalse($kit->nonceValid(self::IP, self::NOW, str_repeat('0', 32)));
        self::assertFalse($kit->nonceValid(self::IP, self::NOW, substr($kit->nonce(self::IP, self::NOW), 0, -1)));
        self::assertFalse($kit->nonceValid(null, self::NOW, $kit->nonce(self::IP, self::NOW)));
        self::assertFalse($kit->nonceValid(self::IP, self::NOW, null));
    }

    public function testTokenRoundTripsWithinTheHourAndExpiresAfter(): void
    {
        $kit = new Kit('secret');
        $t = $kit->issue(self::IP, self::NOW);
        self::assertTrue($kit->tokenValid(self::IP, self::NOW + 3_599_000, $t));
        self::assertFalse($kit->tokenValid(self::IP, self::NOW + 3_600_000, $t));
    }

    public function testTokenIsBoundToTheIpAndUnforgeable(): void
    {
        $kit = new Kit('secret');
        $t = $kit->issue(self::IP, self::NOW);
        self::assertFalse($kit->tokenValid('203.0.113.10', self::NOW, $t));
        [$exp, $mac] = explode('.', $t);
        self::assertFalse($kit->tokenValid(self::IP, self::NOW, $exp . '.' . str_repeat('0', strlen($mac))));
        self::assertFalse($kit->tokenValid(self::IP, self::NOW, ((int) $exp + 1) . '.' . $mac));
        self::assertFalse($kit->tokenValid(null, self::NOW, $t));   // no ip: never
        foreach ([null, '', 'x', '.mac', 'notanumber.mac'] as $junk) {
            self::assertFalse($kit->tokenValid(self::IP, self::NOW, $junk));
        }
    }

    public function testTokenRefusesAnExpiryFurtherOutThanTheTtl(): void
    {
        $kit = new Kit('secret');
        $far = $kit->issue(self::IP, self::NOW + 10_000_000);   // minted "in the future": exp > now + TTL
        self::assertFalse($kit->tokenValid(self::IP, self::NOW, $far));
    }

    public function testProofOfWorkAcceptsA16BitSolutionAndRejectsAnythingElse(): void
    {
        $kit = new Kit('secret');
        $nonce = $kit->nonce(self::IP, self::NOW);
        $sol = self::solve($nonce);
        self::assertTrue($kit->solutionOk($nonce, $sol));
        self::assertTrue($kit->verify(self::IP, self::NOW, $nonce, $sol));
        self::assertFalse($kit->solutionOk($nonce, $sol . '1'));
        self::assertFalse($kit->solutionOk($nonce, str_repeat('x', 33)));
        self::assertFalse($kit->solutionOk($nonce, null));
        $forged = str_repeat('f', 32);
        self::assertFalse($kit->verify(self::IP, self::NOW, $forged, self::solve($forged)));   // a forged nonce, even with real work
    }

    public function testPowOkCountsLeadingZeroBits(): void
    {
        self::assertTrue(Format::powOk('0000ffff', 16));
        self::assertFalse(Format::powOk('0001ffff', 16));
        self::assertTrue(Format::powOk('00007fff', 17));
        self::assertFalse(Format::powOk('0000ffff', 17));
        self::assertTrue(Format::powOk('0', 4));
        self::assertFalse(Format::powOk('', 4));
        self::assertFalse(Format::powOk('000g', 13));
    }

    public function testCookieString(): void
    {
        self::assertSame('_cch=1.abc; Path=/; Max-Age=3600; HttpOnly; SameSite=Lax', Format::challengeCookie('1.abc', false));
        self::assertStringEndsWith('; Secure', Format::challengeCookie('1.abc', true));
    }

    public function testSafeReturnToKeepsOnlyASameSitePath(): void
    {
        self::assertSame('/a/b?c=1', Format::safeReturnTo('/a/b?c=1'));
        foreach ([null, '', 'https://evil', '//evil', '/\\evil', '/a b', "/\xc3\xa9", '/' . str_repeat('a', 2048), 'relative'] as $bad) {
            self::assertSame('/', Format::safeReturnTo($bad), (string) $bad);
        }
    }

    public function testWantsHtml(): void
    {
        self::assertTrue(Format::wantsHtml('text/html,*/*', null));
        self::assertTrue(Format::wantsHtml('text/html', 'document'));
        self::assertFalse(Format::wantsHtml('application/json', null));
        self::assertFalse(Format::wantsHtml('text/html', 'empty'));
        self::assertFalse(Format::wantsHtml(null, null));
    }

    public function testFormBodyLastValueWinsAndNeverThrows(): void
    {
        self::assertSame(['a' => '2', 'b' => 'x y', 'c' => '', '%zz' => '%zz'], Format::parseFormBody('a=1&b=x+y&a=2&c&%zz=%zz'));
        self::assertSame(['nonce' => 'abc', 'solution' => '7', 'to' => '/x?y=1'], Format::parseFormBody('nonce=abc&solution=7&to=%2Fx%3Fy%3D1'));
        self::assertSame([], Format::parseFormBody(''));
    }

    public function testEscaping(): void
    {
        self::assertSame('a&lt;b&gt;&amp;&quot;c&#39;', Format::escapeAttr('a<b>&"c\''));
        self::assertSame('"\\u003c/script>"', Format::escapeScript('</script>'));
    }

    public function testSplitToken(): void
    {
        self::assertSame([12, 'abc'], Format::splitToken('12.abc'));
        foreach ([null, '', '.abc', '12.', 'x.abc', '12'] as $bad) {
            self::assertNull(Format::splitToken($bad), (string) $bad);
        }
    }

    public function testPageIsSelfContainedAndEscaped(): void
    {
        $html = Page::render(nonce: str_repeat('ab', 16), action: '/__camada/challenge', to: '/x"><script>');
        self::assertStringStartsWith('<!doctype html>', $html);
        $head = str_replace('http-equiv', '', explode('<script>', $html)[0]);
        self::assertStringNotContainsString('http', $head);   // no external assets before the solver
        self::assertStringContainsString('action="/__camada/challenge"', $html);
        self::assertStringContainsString('value="/x&quot;&gt;&lt;script&gt;"', $html);
        self::assertStringNotContainsString('crypto.subtle', $html);
        self::assertStringContainsString('__camadaSha256Words', $html);
        self::assertStringContainsString('shift=16', $html);
    }

    public function testPageDifficultyIsClamped(): void
    {
        self::assertStringContainsString('shift=0', Page::render(nonce: str_repeat('a', 32), action: '/v', to: '/', bits: 99));
        self::assertStringContainsString('shift=31', Page::render(nonce: str_repeat('a', 32), action: '/v', to: '/', bits: 0));
    }

    public function testPageIsByteIdenticalToTheFamilyPage(): void
    {
        // the page camada-python (and @camada/core) serve, pinned by its digest so a stray edit shows up by name:
        // sha256 of challenge_page(nonce='0'*32, action='/__camada/challenge', to='/') from camada-python
        $html = Page::render(nonce: str_repeat('0', 32), action: '/__camada/challenge', to: '/');
        self::assertSame('88f557a17656625f254ec7e99ab26c93470fcafe5548e04a8b307d6255323ecc', hash('sha256', $html));
        self::assertSame(3789, strlen($html));
    }
}
