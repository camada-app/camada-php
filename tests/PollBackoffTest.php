<?php

declare(strict_types=1);

namespace Camada\Tests;

use Camada\Camada;
use Camada\Guarded;
use Camada\Req;
use Camada\Runtime\Cache;
use Camada\Snapshot\Client;
use Camada\Snapshot\MatchInput;
use Camada\Transport\HttpRequest;
use Camada\Transport\HttpResponse;
use Camada\Transport\TransportInterface;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/**
 * Snapshot poll pacing (camada-all-pbv9): a failed poll keeps the blocks and gates the next
 * self-initiated poll, across workers through state.json. Driven by camada-core's
 * test/fixtures/poll/backoff.json; fails by name when the fixture is missing, never skips.
 */
final class PollBackoffTest extends TestCase
{
    private string $dir;

    protected function setUp(): void
    {
        Guarded::useStamp(null);
        $this->dir = sys_get_temp_dir() . '/camada-backoff-' . getmypid() . '-' . random_int(1, 1_000_000);
    }

    protected function tearDown(): void
    {
        foreach (glob($this->dir . '/*') ?: [] as $f) {
            @unlink($f);
        }
        @rmdir($this->dir);
    }

    /** @return array<string, mixed> */
    private static function fx(): array
    {
        return Fixtures::json('poll/backoff.json');
    }

    /** @return iterable<string, array{array<string, mixed>}> */
    public static function delayCases(): iterable
    {
        /** @var list<array<string, mixed>> $cases */
        $cases = self::fx()['delay'];
        foreach ($cases as $c) {
            yield (string) $c['name'] => [$c];
        }
    }

    /** @return iterable<string, array{array<string, mixed>}> */
    public static function timelines(): iterable
    {
        /** @var list<array<string, mixed>> $tls */
        $tls = self::fx()['timelines'];
        foreach ($tls as $t) {
            yield (string) $t['name'] => [$t];
        }
    }

    /** @param array<string, mixed> $c */
    #[DataProvider('delayCases')]
    public function testNextPollDelay(array $c): void
    {
        $got = Client::nextPollDelay((int) $c['status'], $c['retryAfter'], (float) $c['refreshSeconds']);
        if ($c['expectDelaySeconds'] === null) {
            self::assertNull($got);
        } else {
            self::assertEqualsWithDelta((float) $c['expectDelaySeconds'], $got, 1e-9);
        }
    }

    /** @param array<string, mixed> $tl */
    #[DataProvider('timelines')]
    public function testTimeline(array $tl): void
    {
        $a = new FakeAnalyst();
        $now = (float) $tl['clockBase'];
        $c = new Client('https://analyst.test/snapshot', 'snap-test', new Cache($this->dir), $a, refreshS: (float) $tl['refreshSeconds'], clock: static function () use (&$now): float {
            return $now;
        });
        $blockedIp = (string) self::fx()['blockedIp'];
        /** @var list<array<string, mixed>> $steps */
        $steps = $tl['steps'];
        foreach ($steps as $st) {
            $now = (float) $tl['clockBase'] + (float) $st['t'];
            $label = $tl['name'] . ' @ t=' . $st['t'];
            $c->invalidate();
            self::assertSame($st['poll'], $c->due(), $label);
            if (!$st['poll']) {
                continue;
            }
            /** @var array{status: int, retryAfter?: string} $r */
            $r = $st['respond'];
            $a->snapshotDown = $r['status'] === 0;
            $a->snapshotStatus = in_array($r['status'], [0, 200], true) ? null : $r['status'];
            $a->snapshotRetryAfter = $r['retryAfter'] ?? null;
            $c->refresh();
            /** @var array{cold: bool, blocked: bool} $after */
            $after = $st['after'];
            $v = $c->verdict(new MatchInput(ip: $blockedIp));
            self::assertSame($after['cold'], $v->reason === 'cold', $label . ' cold');
            self::assertSame($after['blocked'], $v->block, $label . ' blocked');
        }
    }

    public function testTheGateIsSharedByEveryWorkerOnTheCacheDir(): void
    {
        $a = new FakeAnalyst();
        $now = 1000.0;
        $clock = static function () use (&$now): float {
            return $now;
        };
        $mk = fn (): Client => new Client('https://analyst.test/snapshot', 'snap-test', new Cache($this->dir), $a, refreshS: 30.0, clock: $clock);
        $mk()->refresh();
        $now = 1028.0;
        $a->snapshotStatus = 503;
        $a->snapshotRetryAfter = '30';
        $mk()->refresh();   // fails: gates every worker
        self::assertCount(2, $a->snapshotRequests);
        $other = $mk();
        $now = 1040.0;
        self::assertFalse($other->due());
        $other->refresh(false);   // an armed kick that lost the race does nothing
        self::assertCount(2, $a->snapshotRequests);
        $now = 1058.1;
        self::assertTrue($other->due());
    }

    public function testAnArmedRefreshRechecksAfterTakingTheLock(): void
    {
        $a = new FakeAnalyst();
        $now = 1000.0;
        $c = new Client('https://analyst.test/snapshot', 'snap-test', new Cache($this->dir), $a, refreshS: 30.0, clock: static function () use (&$now): float {
            return $now;
        });
        $c->refresh();
        $now = 1028.0;
        self::assertTrue($c->due());   // armed while stale ...
        (new Client('https://analyst.test/snapshot', 'snap-test', new Cache($this->dir), $a, refreshS: 30.0, clock: static function () use (&$now): float {
            return $now;
        }))->refresh();                // ... another worker polls first ...
        $n = count($a->snapshotRequests);
        $c->refresh(false);            // ... so the armed one finds it fresh
        self::assertCount($n, $a->snapshotRequests);
    }

    public function testAClockStepBackReadsAsStaleAndOpen(): void
    {
        $a = new FakeAnalyst();
        $now = 1000.0;
        $c = new Client('https://analyst.test/snapshot', 'snap-test', new Cache($this->dir), $a, refreshS: 30.0, clock: static function () use (&$now): float {
            return $now;
        });
        $c->refresh();
        $now = 500.0;   // loaded_at is now in the future
        $c->invalidate();
        self::assertTrue($c->stale());
        $a->snapshotStatus = 503;
        $now = 1028.0;
        $c->refresh();   // next_poll_at = 1033
        $now = 100.0;    // stepped back by far more than one cadence
        $c->invalidate();
        self::assertTrue($c->due());
    }

    /** One request through Camada::handle and the post-response phase (deferred slots armed, then run). */
    private static function hit(Camada $e): void
    {
        $e->handle(new Req('GET', '/', peer: '172.16.0.9'));
        $e->deferred()->runTasks();
    }

    /**
     * Rewrites state.json the way time passing would.
     *
     * @param array<string, mixed> $patch
     */
    private function patchState(array $patch): void
    {
        $this->patchStateIn($this->dir, $patch);
    }

    public function testTheRequestPathHonoursAClosedGateAcrossEngines(): void
    {
        $a = new FakeAnalyst();
        $e1 = Driver::engineWith($a, $this->dir, [], refreshS: 60.0);
        $e2 = Driver::engineWith($a, $this->dir, [], refreshS: 60.0);
        Driver::loaded($e1);
        self::assertCount(1, $a->snapshotRequests);
        $this->patchState(['loaded_at' => microtime(true) - 100]);   // stale
        $a->snapshotStatus = 503;
        $a->snapshotRetryAfter = '30';
        for ($i = 0; $i < 6; $i++) {
            self::hit($i % 2 === 0 ? $e1 : $e2);
        }
        self::assertCount(2, $a->snapshotRequests);   // the first request polled; the gate held for the rest, on both engines
        $this->patchState(['next_poll_at' => microtime(true) - 1]);   // 30 s later
        self::hit($e2);
        self::assertCount(3, $a->snapshotRequests);
    }

    public function testAThrowingTransportIsLoggedAndStillGated(): void
    {
        $a = new FakeAnalyst();
        $throwing = false;
        $t = new class ($a, $throwing) implements TransportInterface {
            public function __construct(private readonly FakeAnalyst $a, private bool &$throwing)
            {
            }

            public function send(HttpRequest $req): HttpResponse
            {
                if ($this->throwing) {
                    throw new \RuntimeException('socket exploded');
                }
                return $this->a->send($req);
            }
        };
        $log = $this->dir . '.log';
        $prev = ini_set('error_log', $log);
        try {
            foreach (['cold', 'warm'] as $phase) {
                @unlink($log);
                Guarded::useStamp(null);
                $c = new Client('https://analyst.test/snapshot', 'snap-test', new Cache($this->dir . $phase), $t, refreshS: 30.0);
                if ($phase === 'warm') {
                    $c->refresh();
                    $this->patchStateIn($this->dir . $phase, ['loaded_at' => microtime(true) - 100]);
                    $c->invalidate();
                }
                $throwing = true;
                $c->refresh();
                $throwing = false;
                $c->invalidate();
                self::assertStringContainsString('socket exploded', (string) @file_get_contents($log), $phase);
                self::assertFalse($c->due(), $phase . ': gated as status 0');
            }
        } finally {
            ini_set('error_log', $prev === false ? '' : $prev);
            foreach (['cold', 'warm'] as $phase) {
                foreach (glob($this->dir . $phase . '/*') ?: [] as $f) {
                    @unlink($f);
                }
                @rmdir($this->dir . $phase);
            }
            @unlink($log);
        }
    }

    /** @param array<string, mixed> $patch */
    private function patchStateIn(string $dir, array $patch): void
    {
        $cache = new Cache($dir);
        $cache->writeJson('state.json', array_merge($cache->readJson('state.json') ?? [], $patch));
    }
}
