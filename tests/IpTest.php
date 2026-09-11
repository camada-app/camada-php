<?php

declare(strict_types=1);

namespace Camada\Tests;

use Camada\Config;
use Camada\Ip;
use PHPUnit\Framework\TestCase;

/**
 * Client-IP resolution under the tenant's trusted-proxy config. The default is the socket peer:
 * raw X-Forwarded-For is attacker-writable and never trusted without explicit configuration.
 */
final class IpTest extends TestCase
{
    public function testSocketPeerWithoutConfigEvenWhenXffIsPresent(): void
    {
        self::assertSame('10.0.0.1', Ip::resolve('10.0.0.1', '203.0.113.66', null));
        self::assertSame('10.0.0.1', Ip::resolve('10.0.0.1', '203.0.113.66', ['mode' => 'none']));
    }

    public function testV4MappedPeerIsUnwrapped(): void
    {
        self::assertSame('10.0.0.1', Ip::resolve('::ffff:10.0.0.1', null, null));
        self::assertNull(Ip::resolve(null, '1.2.3.4', null));
    }

    public function testHopsCountsFromTheRight(): void
    {
        self::assertSame('198.51.100.7', Ip::resolve('10.0.0.1', '203.0.113.66, 198.51.100.7', ['mode' => 'hops', 'hops' => 1]));
        self::assertSame('203.0.113.66', Ip::resolve('10.0.0.1', '203.0.113.66, 198.51.100.7', ['mode' => 'hops', 'hops' => 2]));
        self::assertSame('10.0.0.1', Ip::resolve('10.0.0.1', '203.0.113.66', ['mode' => 'hops', 'hops' => 2]));   // out of range: the peer
    }

    public function testVercelTakesTheRightmostEntry(): void
    {
        self::assertSame('203.0.113.66', Ip::resolve('10.0.0.1', 'spoof, 203.0.113.66', ['mode' => 'vercel']));
    }

    public function testCidrsSkipsTrustedProxiesFromTheRight(): void
    {
        $cfg = ['mode' => 'cidrs', 'cidrs' => ['10.0.0.0/8', '2001:db8::/32']];
        self::assertSame('203.0.113.66', Ip::resolve('10.0.0.1', '203.0.113.66, 10.1.2.3, 10.9.9.9', $cfg));
        self::assertSame('203.0.113.66', Ip::resolve('10.0.0.1', '203.0.113.66, 2001:db8::5', $cfg));
        self::assertSame('10.0.0.1', Ip::resolve('10.0.0.1', '10.1.2.3', $cfg));            // everything trusted: the peer
        self::assertSame('10.0.0.1', Ip::resolve('10.0.0.1', 'not-an-ip, 10.1.2.3', $cfg)); // candidate must parse
        self::assertSame('10.1.2.3', Ip::resolve('10.0.0.1', '10.1.2.3', ['mode' => 'cidrs', 'cidrs' => ['junk', '10.0.0.0/99']]));   // unparsable cidrs trust nothing
    }

    public function testEnvStringForms(): void
    {
        self::assertNull(Config::parseTrustedProxyEnv(null));
        self::assertSame(['mode' => 'none'], Config::parseTrustedProxyEnv('none'));
        self::assertSame(['mode' => 'vercel'], Config::parseTrustedProxyEnv('vercel'));
        self::assertSame(['mode' => 'hops', 'hops' => 2], Config::parseTrustedProxyEnv('hops:2'));
        self::assertNull(Config::parseTrustedProxyEnv('hops:0'));
        self::assertNull(Config::parseTrustedProxyEnv('hops:x'));
        self::assertSame(['mode' => 'cidrs', 'cidrs' => ['10.0.0.0/8', '192.0.2.0/24']], Config::parseTrustedProxyEnv('cidrs:10.0.0.0/8, 192.0.2.0/24'));
        self::assertNull(Config::parseTrustedProxyEnv('cidrs:'));
        self::assertNull(Config::parseTrustedProxyEnv('bogus'));
    }
}
