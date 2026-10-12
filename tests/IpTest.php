<?php

declare(strict_types=1);

namespace Camada\Tests;

use Camada\Config;
use Camada\Http\Sapi;
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
        self::assertSame('10.0.0.1', Ip::resolve('10.0.0.1', '8.8.8.8, 2001:db8::1:', $cfg));   // a non-IP entry is never a trusted hop
        self::assertSame('10.1.2.3', Ip::resolve(null, '10.1.2.3', ['mode' => 'cidrs', 'cidrs' => ['junk', '10.0.0.0/99']]));   // unparsable cidrs trust nothing
        self::assertSame('10.0.0.1', Ip::resolve('10.0.0.1', '10.1.2.3', ['mode' => 'cidrs', 'cidrs' => ['junk', '10.0.0.0/99']]));   // ... not even the peer
    }

    /** The Cloudflare preset as the dashboard stores it (the 22 published ranges), plus App Engine's 169.254.0.0/16. */
    private const CF = ['173.245.48.0/20', '103.21.244.0/22', '103.22.200.0/22', '103.31.4.0/22', '141.101.64.0/18', '108.162.192.0/18',
        '190.93.240.0/20', '188.114.96.0/20', '197.234.240.0/22', '198.41.128.0/17', '162.158.0.0/15', '104.16.0.0/13', '104.24.0.0/14',
        '172.64.0.0/13', '131.0.72.0/22', '2400:cb00::/32', '2606:4700::/32', '2803:f800::/32', '2405:b500::/32', '2405:8100::/32',
        '2a06:98c0::/29', '2c0f:f248::/32'];

    public function testTrialsightsShapeResolvesToTheClient(): void
    {
        // camada-all-yfc6 Director triage: App Engine's local front end is the socket peer (127.0.0.1)
        // and Google appends 169.254.1.1 after the Cloudflare edge; the client is the entry left of the edge.
        $cfg = ['mode' => 'cidrs', 'cidrs' => [...self::CF, '169.254.0.0/16'], 'cloudflare' => self::CF];
        self::assertSame('198.51.100.9', Ip::resolve('127.0.0.1', '6.6.6.6, 198.51.100.9, 172.64.1.1, 169.254.1.1', $cfg));
        self::assertSame('198.51.100.9', Ip::resolve('127.0.0.1', '6.6.6.6, 198.51.100.9, 169.254.1.1', $cfg));   // a direct appspot hit
        self::assertSame('198.51.100.9', Ip::resolve('::ffff:127.0.0.1', '6.6.6.6, 198.51.100.9, 172.64.1.1, 169.254.1.1', $cfg));
    }

    public function testCidrsDirectHitIgnoresAForgedXff(): void
    {
        // camada-all-yfc6: a peer outside every trusted range did not come through a proxy; it is the client
        $cfg = ['mode' => 'cidrs', 'cidrs' => self::CF, 'cloudflare' => self::CF];
        self::assertSame('203.0.113.200', Ip::resolve('203.0.113.200', '203.0.113.66', $cfg));   // framing a victim
        self::assertSame('203.0.113.200', Ip::resolve('203.0.113.200', '8.8.8.8', $cfg));        // evading a block
        self::assertSame('203.0.113.200', Ip::resolve('203.0.113.200', '8.8.8.8, 172.64.1.1', $cfg));   // a forged edge hop
        self::assertSame('203.0.113.200', Ip::resolve('::FFFF:203.0.113.200', '8.8.8.8', $cfg));
        self::assertSame('198.51.100.9', Ip::resolve('172.64.1.1', '1.2.3.4, 198.51.100.9', $cfg));   // through the edge: unchanged
        self::assertSame('198.51.100.9', Ip::resolve(null, '1.2.3.4, 198.51.100.9, 172.64.1.1', $cfg));   // no peer: the plain walk
        self::assertSame('127.0.0.1', Ip::resolve('172.64.1.1', '127.0.0.1', $cfg));   // loopback is trusted only as the peer
    }

    public function testXffEntriesWithAPortResolveToTheAddress(): void
    {
        // camada-all-0vho: Azure Application Gateway writes ip:port
        $hops = ['mode' => 'hops', 'hops' => 1];
        self::assertSame('203.0.113.66', Ip::resolve('169.254.130.1', '203.0.113.66:51234', $hops));
        self::assertSame('2001:db8::66', Ip::resolve('169.254.130.1', '[2001:db8::66]:51234', $hops));
        self::assertSame('2001:db8::66:8080', Ip::resolve('169.254.130.1', '2001:db8::66:8080', $hops));   // a bare v6 is never split
        self::assertSame('203.0.113.66', Ip::resolve('169.254.130.1', '203.0.113.66, 169.254.1.1:5000', ['mode' => 'cidrs', 'cidrs' => ['169.254.0.0/16']]));
        self::assertSame('169.254.130.1', Ip::resolve('169.254.130.1', '203.0.113.66:80:90', $hops));   // malformed: the peer
        self::assertSame('169.254.130.1', Ip::resolve('169.254.130.1', '[203.0.113.66]:80', $hops));
    }

    public function testSapiPeerIsRemoteAddrAndAUnixListenerWalksXffAlone(): void
    {
        // C6 v3 adapter row (php): the peer is $_SERVER['REMOTE_ADDR'] as given; empty or absent is no peer, so
        // cidrs walks XFF alone (`fastcgi_param REMOTE_ADDR "";` in nginx gives that). php-fpm's own listen socket
        // does not empty it, and nginx listening on a unix socket passes "unix:": not an ip, so no client ip unless
        // the engine is told its listener is a unix socket (EngineTest, unixSocketListener).
        $cfg = ['mode' => 'cidrs', 'cidrs' => self::CF, 'cloudflare' => self::CF];
        $base = ['REQUEST_URI' => '/', 'HTTP_X_FORWARDED_FOR' => '1.2.3.4, 198.51.100.9, 172.64.1.1'];
        foreach ([$base, $base + ['REMOTE_ADDR' => '']] as $server) {
            $req = Sapi::request($server);
            self::assertTrue($req->peer === null || $req->peer === '');
            self::assertSame('198.51.100.9', Ip::resolve($req->peer, $req->header('x-forwarded-for'), $cfg));
        }
        $req = Sapi::request($base + ['REMOTE_ADDR' => '::ffff:203.0.113.200']);
        self::assertSame('203.0.113.200', Ip::resolve($req->peer, $req->header('x-forwarded-for'), $cfg));   // a direct hit: the peer
        $req = Sapi::request($base + ['REMOTE_ADDR' => '/run/php-fpm.sock']);   // a host that reports a path: unreadable, never the walk
        self::assertNull(Ip::resolve($req->peer, $req->header('x-forwarded-for'), $cfg));
        $req = Sapi::request($base + ['REMOTE_ADDR' => 'unix:']);   // nginx's $remote_addr on a unix-socket listener
        self::assertSame('unix:', $req->peer);
        self::assertNull(Ip::resolve($req->peer, $req->header('x-forwarded-for'), $cfg));
    }

    public function testResultIsAlwaysAValidIpOrNull(): void
    {
        // C6 v3: an unreadable peer is never returned verbatim, in any mode
        self::assertNull(Ip::resolve('/run/app.sock', null, null));
        self::assertNull(Ip::resolve('fe80::1%eth0', 'junk', ['mode' => 'hops', 'hops' => 1]));
        self::assertSame('8.8.8.8', Ip::resolve('@', '8.8.8.8', ['mode' => 'vercel']));
        self::assertSame('10.0.0.1', Ip::resolve('10.0.0.1', "8.8.8.8\u{a0}", ['mode' => 'vercel']));   // NBSP is not trimmed
        self::assertSame('8.8.8.8', Ip::resolve('10.0.0.1', "\t8.8.8.8 ", ['mode' => 'vercel']));
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
