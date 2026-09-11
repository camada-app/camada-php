<?php

declare(strict_types=1);

namespace Camada\Tests;

use Camada\IpParse;
use PHPUnit\Framework\TestCase;

/**
 * Ported from the reference edge-analyst src/blocklist.js parsers: ip4 returns -1 on anything
 * unusual; ip6 rejects zone ids and v4-mapped forms. The golden fixtures pin the rest.
 */
final class IpParseTest extends TestCase
{
    public function testIp4DottedQuadToInt(): void
    {
        self::assertSame((203 << 24) | (0 << 16) | (113 << 8) | 66, IpParse::ip4('203.0.113.66'));
        self::assertSame(0xFFFFFFFF, IpParse::ip4('255.255.255.255'));
        self::assertSame(0, IpParse::ip4('0.0.0.0'));
    }

    public function testIp4RejectsAnythingUnusual(): void
    {
        foreach (['', '1.2.3', '1.2.3.4.5', '256.1.1.1', '1..2.3', '01.2.3.4444', 'a.b.c.d', ' 1.2.3.4', "1.2.3.4\n"] as $bad) {
            self::assertSame(-1, IpParse::ip4($bad), $bad);
        }
    }

    public function testIp6FullAndCompressedForms(): void
    {
        self::assertSame([0x20010DB8, 0, 0, 1], IpParse::ip6('2001:db8::1'));
        self::assertSame([0, 0, 0, 1], IpParse::ip6('::1'));
        self::assertSame([0, 0, 0, 0], IpParse::ip6('::'));
        self::assertSame([0xFE800000, 0, 0, 1], IpParse::ip6('fe80:0:0:0:0:0:0:1'));
        self::assertSame([0x20010DB8, 0xCAFE0000, 0, 0], IpParse::ip6('2001:DB8:CAFE::'));
    }

    public function testIp6RejectsZoneIdsMappedV4AndMalformed(): void
    {
        foreach (['fe80::1%eth0', '::ffff:1.2.3.4', '1:2:3:4:5:6:7:8:9', '1::2::3', '12345::', 'g::1', '1:2:3:4:5:6:7', ':1::'] as $bad) {
            self::assertNull(IpParse::ip6($bad), $bad);
        }
    }
}
