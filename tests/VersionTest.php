<?php

declare(strict_types=1);

namespace Camada\Tests;

use Camada\Version;
use PHPUnit\Framework\TestCase;

/**
 * The SDK's wire identity (SDK-03): x-camada-sdk: @camada/php/<version>. One literal in
 * Version.php is the single source every sibling drift guard parses (composer.json carries no
 * version field: Packagist reads tags).
 */
final class VersionTest extends TestCase
{
    // edge-analyst src/freshness.js SDK_RE: anything else is silently dropped from sdk_versions.
    private const ANALYST_SDK_RE = '~^@?[a-z0-9._-]+(/[a-z0-9._-]+)?/\d+\.\d+\.\d+[a-z0-9.-]*$~i';

    public function testSdkIdIsTheFamilyWireIdentity(): void
    {
        self::assertSame('@camada/php/' . Version::VERSION, Version::SDK_ID);
        self::assertMatchesRegularExpression(self::ANALYST_SDK_RE, Version::SDK_ID);
        self::assertLessThanOrEqual(64, strlen(Version::SDK_ID));
        self::assertMatchesRegularExpression('/^\d+\.\d+\.\d+$/', Version::VERSION);
    }

    public function testTheLiteralIsWhatTheDriftGuardsParse(): void
    {
        $src = (string) file_get_contents(__DIR__ . '/../src/Version.php');
        self::assertSame(1, preg_match("/public const VERSION = '([^']+)';/", $src, $m));
        self::assertSame(Version::VERSION, $m[1] ?? null);
    }

    public function testComposerNameIsThePackagistName(): void
    {
        $composer = json_decode((string) file_get_contents(__DIR__ . '/../composer.json'), true);
        self::assertIsArray($composer);
        self::assertSame('camada/camada', $composer['name']);
        self::assertArrayNotHasKey('version', $composer, 'Packagist reads tags; the literal lives in Version.php');
    }
}
