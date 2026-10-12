<?php

declare(strict_types=1);

namespace Camada\Tests;

use Camada\Events\Builder;
use Camada\Ip;
use Camada\Req;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/**
 * The SDK conformance cases (contract C6) every server SDK runs: client-IP resolution
 * (camada-all-0vho XFF ports, camada-all-yfc6 peer-first cidrs walk) and the Referer scrub
 * (camada-all-ijsa). The files live in camada-core/test/fixtures and are missing → fail by name,
 * never skip. No case is skipped here.
 *
 * @phpstan-import-type TrustedProxy from \Camada\Config
 */
final class SdkConformanceTest extends TestCase
{
    /** @return iterable<string, array{?string, ?string, TrustedProxy|null, ?string}> */
    public static function ipCases(): iterable
    {
        $doc = Fixtures::json('ip/resolve.json');
        /** @var array<string, TrustedProxy|null> $configs */
        $configs = $doc['configs'];
        /** @var list<array{id: string, config: string, peer: ?string, xff: ?string, expect: ?string}> $cases */
        $cases = $doc['cases'];
        foreach ($cases as $c) {
            self::assertArrayHasKey($c['config'], $configs, $c['id']);
            yield $c['id'] => [$c['peer'], $c['xff'], $configs[$c['config']], $c['expect']];
        }
    }

    /** @param TrustedProxy|null $cfg */
    #[DataProvider('ipCases')]
    public function testResolveClientIp(?string $peer, ?string $xff, ?array $cfg, ?string $expect): void
    {
        self::assertSame($expect, Ip::resolve($peer, $xff, $cfg));
    }

    /** @return iterable<string, array{?string, ?string, list<string>}> */
    public static function refererCases(): iterable
    {
        /** @var list<array{id: string, referer: ?string, ref: ?string, absent?: list<string>}> $cases */
        $cases = Fixtures::json('redact/referer.json')['cases'];
        foreach ($cases as $c) {
            yield $c['id'] => [$c['referer'], $c['ref'], $c['absent'] ?? []];
        }
    }

    /** @param list<string> $absent */
    #[DataProvider('refererCases')]
    public function testRefererRedaction(?string $referer, ?string $ref, array $absent): void
    {
        $headers = [['accept', 'text/html']];
        if ($referer !== null) {
            $headers[] = ['referer', $referer];
        }
        $req = new Req(method: 'GET', path: '/api/me', query: '', host: 'shop.test', httpVersion: '1.1', headers: $headers);
        $ev = Builder::wireEvent($req, ip: '1.2.3.4', tap: 'sdk-php', rid: 'r1', sid: null, newSession: false);
        self::assertSame($ref, $ev['ref']);
        $json = json_encode($ev, JSON_THROW_ON_ERROR | JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
        foreach ($absent as $secret) {
            self::assertStringNotContainsString($secret, $json);
        }
    }
}
