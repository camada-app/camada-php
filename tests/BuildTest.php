<?php

declare(strict_types=1);

namespace Camada\Tests;

use Camada\Events\Builder;
use Camada\Req;
use PHPUnit\Framework\TestCase;

/**
 * The wire event reproduces the collector's record(); HDRS bit order is pinned by the shared
 * fixture (ConformanceTest) — here the derived counters and the credential rules.
 */
final class BuildTest extends TestCase
{
    /** @param list<array{string, string}> $headers */
    private static function req(array $headers, string $query = ''): Req
    {
        return new Req(method: 'GET', path: '/p', query: $query, host: 'x.test', httpVersion: '1.1', headers: $headers);
    }

    public function testAuthSchemeOnlyEverShipsAScheme(): void
    {
        self::assertSame('Bearer', Builder::authScheme('Bearer abc.def'));
        self::assertSame('Basic', Builder::authScheme('Basic dXNlcjpwYXNz'));
        self::assertNull(Builder::authScheme('rawtoken'));
        self::assertNull(Builder::authScheme(' Bearer x'));
        self::assertNull(Builder::authScheme(str_repeat('a', 17) . ' x'));
        self::assertNull(Builder::authScheme(null));
    }

    public function testEventFieldsAndCounters(): void
    {
        $headers = [['accept', 'text/html'], ['cookie', 'a=1; b=2'], ['authorization', 'Bearer t'], ['accept', '*/*'], ['user-agent', 'ua']];
        $ev = Builder::wireEvent(self::req($headers, '?x=1&token=t&&y'), ip: '1.2.3.4', tap: 'sdk-php', rid: 'r1', sid: 's1', newSession: true);
        self::assertSame('sdk-php', $ev['tap']);
        self::assertSame('r1', $ev['rid']);
        self::assertSame('s1', $ev['sid']);
        self::assertSame(1, $ev['ns']);
        self::assertSame('GET', $ev['m']);
        self::assertSame('x.test', $ev['h']);
        self::assertSame('/p', $ev['p']);
        self::assertSame('HTTP/1.1', $ev['proto']);
        self::assertSame('?x=1&token=~r&&y', $ev['q']);
        self::assertSame(3, $ev['qn']);
        self::assertSame('text/html', $ev['acc']);   // first occurrence wins
        self::assertSame('Bearer', $ev['auth']);
        self::assertSame(2, $ev['ck']);
        self::assertSame(5, $ev['hn']);
        self::assertSame(array_sum(array_map(static fn (array $h): int => strlen($h[0]) + strlen($h[1]), $headers)), $ev['hb']);
        self::assertSame('accept,cookie,authorization,accept,user-agent', $ev['hord']);
        self::assertSame((1 << array_search('accept', Builder::HDRS, true)) | (1 << array_search('cookie', Builder::HDRS, true)) | (1 << array_search('authorization', Builder::HDRS, true)), $ev['hm']);
        self::assertSame('ua', $ev['ua']);
        self::assertNull($ev['st']);
        self::assertNull($ev['dur']);
        self::assertIsInt($ev['ts']);
        self::assertArrayNotHasKey('ja4', $ev);
        self::assertSame(['st', 'dur'], array_slice(array_keys($ev), -2));   // st/dur close the row, as the collector writes it
    }

    public function testEventWithoutHeadersOrIp(): void
    {
        $ev = Builder::wireEvent(self::req([]), ip: null, tap: 'sdk-php', rid: 'r');
        self::assertNull($ev['ip']);
        self::assertNull($ev['sid']);
        self::assertSame(0, $ev['ns']);
        self::assertSame(0, $ev['hm']);
        self::assertSame(0, $ev['hn']);
        self::assertSame(0, $ev['hb']);
        self::assertSame(0, $ev['ck']);
        self::assertSame('', $ev['hord']);
        self::assertSame(0, $ev['qn']);
        self::assertSame('', $ev['q']);
    }

    public function testHordAndQueryAreCapped(): void
    {
        $headers = [];
        for ($i = 0; $i < 1000; $i++) {
            $headers[] = ["x-{$i}", 'v'];
        }
        $ev = Builder::wireEvent(self::req($headers, '?' . str_repeat('a', 600)), ip: '1.2.3.4', tap: 'sdk-php', rid: 'r');
        self::assertSame(2048, strlen((string) $ev['hord']));
        self::assertSame(512, strlen((string) $ev['q']));
    }

    public function testJa4RidesOnlyWhenKnown(): void
    {
        $ev = Builder::wireEvent(self::req([]), ip: null, tap: 'sdk-php', rid: 'r', ja4: 't13d');
        self::assertSame('t13d', $ev['ja4']);
    }

    public function testReqHeaderJoinsRepeatsTheWayNodeDoes(): void
    {
        $req = self::req([['cookie', 'a=1'], ['cookie', 'b=2'], ['accept', 'x'], ['accept', 'y']]);
        self::assertSame('a=1; b=2', $req->header('cookie'));
        self::assertSame('x, y', $req->header('accept'));
        self::assertNull($req->header('user-agent'));
    }
}
