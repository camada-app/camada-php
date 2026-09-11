<?php

declare(strict_types=1);

namespace Camada\Tests;

use Camada\Events\Spool;
use Camada\Guarded;
use Camada\Runtime\Cache;
use Camada\Runtime\Lock;
use PHPUnit\Framework\TestCase;

/**
 * Events\Spool: the file-backed twin of the event queue. Rows are appended to events.ndjson
 * under the spool lock; the post-response phase ships it to POST /e in slices of ≤ 1000 when it
 * is due (≥ 500 rows or 15 s since the last flush). Nothing here may ever throw into the
 * request path, and a dead ingest must cost nothing but dropped telemetry.
 */
final class SpoolTest extends TestCase
{
    private string $dir;

    protected function setUp(): void
    {
        Guarded::useStamp(null);   // each test judges its own log lines
        $this->dir = sys_get_temp_dir() . '/camada-spool-' . getmypid() . '-' . random_int(1, 1_000_000);
    }

    protected function tearDown(): void
    {
        foreach (glob($this->dir . '/*') ?: [] as $f) {
            @unlink($f);
        }
        @rmdir($this->dir);
    }

    private function spool(FakeAnalyst $a, int $maxBatch = 500, int $maxQueue = 2000, float $flushS = 15.0): Spool
    {
        return new Spool(new Cache($this->dir), $a, 'https://analyst.test', 'tok-test', sdk: '@camada/php/0.0.0', maxBatch: $maxBatch, maxQueue: $maxQueue, flushS: $flushS);
    }

    public function testFlushPostsAJsonArrayWithTheTenantAndSdkHeaders(): void
    {
        $a = new FakeAnalyst();
        $q = $this->spool($a);
        $q->push(['p' => '/']);
        self::assertSame(1, $q->size());
        $q->flush();
        self::assertSame([[['p' => '/']]], $a->events);
        self::assertSame(['@camada/php/0.0.0'], $a->sdkHeaders);
        self::assertSame(0, $q->size());
        self::assertFileDoesNotExist($this->dir . '/events.ndjson');
    }

    public function testShipsWhenTheBatchSizeIsReached(): void
    {
        $a = new FakeAnalyst();
        $q = $this->spool($a, maxBatch: 3, flushS: 60);
        for ($i = 0; $i < 2; $i++) {
            $q->push(['i' => $i]);
            self::assertFalse($q->due());
            $q->shipIfDue();
        }
        self::assertSame([], $a->events);
        $q->push(['i' => 2]);
        self::assertTrue($q->due());
        $q->shipIfDue();
        self::assertSame([[['i' => 0], ['i' => 1], ['i' => 2]]], $a->events);
    }

    public function testShipsOnTheInterval(): void
    {
        $a = new FakeAnalyst();
        $q = $this->spool($a, flushS: 0.05);
        $q->push(['i' => 1]);
        $q->shipIfDue();
        self::assertSame([], $a->events);   // the first push starts the clock, as the queue's flush thread did
        usleep(80_000);
        self::assertTrue($q->due());
        $q->shipIfDue();
        self::assertSame([[['i' => 1]]], $a->events);
        self::assertFalse($q->due());   // nothing spooled: not due, whatever the clock says
    }

    public function testDrainsInSlicesOf1000(): void
    {
        $a = new FakeAnalyst();
        $q = $this->spool($a, maxBatch: 5000, maxQueue: 5000);
        for ($i = 0; $i < 1500; $i++) {
            $q->push(['i' => $i]);
        }
        $q->flush();
        self::assertSame([1000, 500], array_map('count', $a->events));
        self::assertSame(['i' => 1499], $a->events[1][499]);
    }

    public function testDropsOldestBeyondTheQueueCap(): void
    {
        // over the cap the appender keeps the newest half: one rewrite per 1000 rows, not one per push
        $a = new FakeAnalyst();
        $q = $this->spool($a, maxBatch: 100, maxQueue: 4, flushS: 60);
        for ($i = 0; $i < 5; $i++) {
            $q->push(['i' => $i]);
        }
        self::assertSame(2, $q->size());
        self::assertSame(3, $q->dropped());
        $q->push(['i' => 5]);
        self::assertSame(3, $q->size());
        $q->flush();
        self::assertSame([[['i' => 3], ['i' => 4], ['i' => 5]]], $a->events);
    }

    public function testDeadIngestDropsSilentlyAndRecovers(): void
    {
        $a = new FakeAnalyst();
        $a->ingestDown = true;
        $q = $this->spool($a);
        $q->push(['i' => 1]);
        $prev = ini_set('error_log', $this->dir . '/error.log');
        try {
            $q->flush();
        } finally {
            ini_set('error_log', $prev === false ? '' : $prev);
        }
        self::assertSame(1, $q->dropped());
        self::assertSame(0, $q->size());
        self::assertStringContainsString('[camada] suppressed error', (string) file_get_contents($this->dir . '/error.log'));
        $a->ingestDown = false;
        $q->push(['i' => 2]);
        $q->flush();
        self::assertSame([[['i' => 2]]], $a->events);
    }

    public function testPushNeverThrows(): void
    {
        $a = new FakeAnalyst();
        $q = new Spool(new Cache($this->dir), $a, 'https://analyst.test', 'tok-test', sdk: 'x');
        $prev = ini_set('error_log', $this->dir . '.log');
        try {
            $q->push(['bad' => "\xB1\x31"]);   // invalid UTF-8 is substituted, not fatal
            self::assertSame(1, $q->size());
            foreach (glob($this->dir . '/*') ?: [] as $f) {
                unlink($f);
            }
            rmdir($this->dir);
            $q->push(['i' => 1]);   // the dir is gone: swallowed and logged, never raised
            self::assertSame(0, $q->size());
        } finally {
            ini_set('error_log', $prev === false ? '' : $prev);
            @unlink($this->dir . '.log');
        }
    }

    public function testASecondShipperYieldsToTheOneInFlight(): void
    {
        $a = new FakeAnalyst();
        $q = $this->spool($a);
        $q->push(['i' => 1]);
        $held = Lock::tryAcquire($this->dir . '/events.lock');   // another worker holds the spool
        self::assertNotNull($held);
        $q->flush();
        self::assertSame([], $a->events);
        self::assertSame(1, $q->size());
        $held->release();
        $q->flush();
        self::assertSame([[['i' => 1]]], $a->events);
    }

    public function testAnOrphanedSendingFileFromACrashedWorkerIsShippedLater(): void
    {
        $a = new FakeAnalyst();
        $q = $this->spool($a);
        file_put_contents($this->dir . '/events.123.abc.sending', "{\"i\":9}\n");
        touch($this->dir . '/events.123.abc.sending', time() - 300);
        $q->push(['i' => 1]);
        $q->flush();
        self::assertSame([[['i' => 1]], [['i' => 9]]], $a->events);
        self::assertSame([], glob($this->dir . '/events.*.sending') ?: []);
    }

    public function testJunkLinesInTheSpoolAreSkipped(): void
    {
        $a = new FakeAnalyst();
        $q = $this->spool($a);
        $q->push(['i' => 1]);
        file_put_contents($this->dir . '/events.ndjson', "not json\n\n", FILE_APPEND);
        $q->push(['i' => 2]);
        $q->flush();
        self::assertSame([[['i' => 1], ['i' => 2]]], $a->events);
    }
}
