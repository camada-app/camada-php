<?php

declare(strict_types=1);

namespace Camada\Tests;

use Camada\BeaconJs;
use PHPUnit\Framework\TestCase;

/**
 * The first-party beacon is @camada/browser's auto build, vendored as a class constant so the
 * package has no runtime file reads (opcache serves it). It must be byte-for-byte the sibling's
 * dist/auto.global.js; the test fails by name (never skips) when that checkout or its build is
 * missing.
 */
final class BeaconJsTest extends TestCase
{
    private static function dist(): string
    {
        $env = getenv('CAMADA_BROWSER_DIST');
        return is_string($env) && $env !== '' ? $env : dirname(__DIR__, 2) . '/camada-browser/dist/auto.global.js';
    }

    public function testVendoredBeaconMatchesTheSiblingBuild(): void
    {
        $dist = self::dist();
        self::assertFileExists($dist, "beacon build missing: {$dist} (run npm run build in camada-browser, or set CAMADA_BROWSER_DIST)");
        $src = (string) file_get_contents($dist);
        self::assertSame($src, BeaconJs::JS, 'run php scripts/sync-beacon.php to re-vendor @camada/browser');
        self::assertSame(hash('sha256', $src), BeaconJs::SHA256);
    }

    public function testBeaconNamesItsOwnVersionAndPostsToFp(): void
    {
        self::assertStringContainsString('"' . BeaconJs::VERSION . '"', BeaconJs::JS);
        self::assertStringContainsString('@camada/browser', BeaconJs::JS);
        self::assertStringContainsString('"fp"', BeaconJs::JS);   // derives the POST target from the script URL's final segment
        $pkg = json_decode((string) file_get_contents(dirname(self::dist(), 2) . '/package.json'), true);
        self::assertIsArray($pkg);
        self::assertSame($pkg['version'], BeaconJs::VERSION);
    }
}
