<?php

declare(strict_types=1);

namespace Camada\Tests;

use PHPUnit\Framework\Assert;

/**
 * The golden snapshot containers live in the camada-core sibling checkout (copied verbatim from
 * edge-analyst, the format owner); the suite fails by name when they are missing rather than
 * skipping, the same stance the web/mkt drift guards take.
 */
final class Fixtures
{
    public static function dir(): string
    {
        $env = getenv('CAMADA_FIXTURES_DIR');
        return is_string($env) && $env !== '' ? $env : dirname(__DIR__, 2) . '/camada-core/test/fixtures';
    }

    public static function path(string $rel): string
    {
        $p = self::dir() . '/' . $rel;
        if (!file_exists($p)) {
            Assert::fail("golden fixture missing: {$p} (no camada-core checkout? set CAMADA_FIXTURES_DIR)");
        }
        return $p;
    }

    public static function bin(string $rel): string
    {
        return (string) file_get_contents(self::path($rel));
    }

    /** @return array<string, mixed> */
    public static function json(string $rel): array
    {
        $v = json_decode((string) file_get_contents(self::path($rel)), true, 512, JSON_THROW_ON_ERROR);
        Assert::assertIsArray($v);
        /** @var array<string, mixed> $v */
        return $v;
    }
}
