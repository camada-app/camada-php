<?php

declare(strict_types=1);

namespace Camada\Tests;

use Camada\Redact;
use PHPUnit\Framework\TestCase;

/**
 * Redaction is not configurable off: credential-looking query values become ~r, body values
 * never ship, user identifiers are HMAC-hashed inside the SDK.
 */
final class RedactTest extends TestCase
{
    public function testScrubQueryByNameAndByValueShape(): void
    {
        self::assertSame('?q=hello&token=~r&x=1', Redact::scrubQuery('?q=hello&token=abc&x=1'));
        self::assertSame('?api_key=~r&PASSWORD=~r', Redact::scrubQuery('?api_key=k&PASSWORD=p'));
        self::assertSame('?t=~r', Redact::scrubQuery('?t=eyJhbGciOi.eyJzdWIiOi.sig'));
        self::assertSame('?h=~r', Redact::scrubQuery('?h=' . str_repeat('a', 32)));
        self::assertSame('?b=~r', Redact::scrubQuery('?b=' . str_repeat('A', 40) . '=='));
        self::assertSame('?flag&x=1', Redact::scrubQuery('?flag&x=1'));   // a bare name is kept as is
    }

    public function testScrubQueryKeepsShapeAndEmpties(): void
    {
        self::assertSame('', Redact::scrubQuery(''));
        self::assertSame('', Redact::scrubQuery(null));
        self::assertSame('?', Redact::scrubQuery('?'));
        self::assertSame('a=1&code=~r', Redact::scrubQuery('a=1&code=2'));   // no leading ? is fine too
    }

    public function testBodyShapeIsNamesAndSizesOnly(): void
    {
        self::assertSame(['email' => 5, 'n' => 2, 'none' => 0, 'arr' => 5], Redact::bodyShape(['email' => 'a@b.c', 'n' => 12, 'none' => null, 'arr' => [1, 2]]));
        self::assertNull(Redact::bodyShape([1]));
        self::assertNull(Redact::bodyShape('str'));
        self::assertSame([], Redact::bodyShape([]));   // an empty JSON object decodes to an empty array
    }

    public function testHashUserIdIsALabelledTruncatedHmac(): void
    {
        $expected = substr(hash_hmac('sha256', 'uid:alice@example.com', 'tok'), 0, 32);
        self::assertSame($expected, Redact::hashUserId('alice@example.com', 'tok'));
        self::assertSame(32, strlen(Redact::hashUserId('x', 'tok')));
    }
}
