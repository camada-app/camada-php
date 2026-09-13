<?php

declare(strict_types=1);

namespace Camada\Tests;

use Camada\Guarded;
use PHPUnit\Framework\TestCase;

/** The fail-open log line: at most one a minute, whether the shared stamp can be written or not. */
final class GuardedTest extends TestCase
{
    private string $log;

    protected function setUp(): void
    {
        $this->log = sys_get_temp_dir() . '/camada-guarded-' . getmypid() . '-' . random_int(1, 1_000_000) . '.log';
    }

    protected function tearDown(): void
    {
        Guarded::useStamp(null);
        @unlink($this->log);
    }

    /** @param list<mixed> $errs */
    private function logged(array $errs): string
    {
        $prev = ini_set('error_log', $this->log);
        try {
            foreach ($errs as $err) {
                Guarded::log($err);
            }
        } finally {
            ini_set('error_log', $prev === false ? '' : $prev);
        }
        return (string) @file_get_contents($this->log);
    }

    public function testTheStampKeepsTheMinuteAcrossProcesses(): void
    {
        $stamp = $this->log . '.stamp';
        Guarded::useStamp($stamp);
        $this->logged(['one']);
        Guarded::useStamp($stamp);   // another process: its own clock is fresh, the stamp is not
        $out = $this->logged(['two', new \RuntimeException('three')]);
        @unlink($stamp);
        self::assertSame(1, substr_count($out, '[camada] suppressed error'), $out);
        self::assertStringContainsString('one', $out);
    }

    public function testAnUnwritableStampFallsBackToTheProcessClock(): void
    {
        // the cache dir cannot be written: the very error being reported must not log once per request
        Guarded::useStamp('/nonexistent-' . getmypid() . '/log.stamp');
        $out = $this->logged(['one', 'two', new \RuntimeException('three')]);
        self::assertSame(1, substr_count($out, '[camada] suppressed error'), $out);
        self::assertStringContainsString('one', $out);
    }
}
