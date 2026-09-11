<?php

declare(strict_types=1);

namespace Camada\Tests;

use Camada\Guarded;
use Camada\Runtime\Cache;
use Camada\Runtime\Lock;
use Camada\Snapshot\Client;
use Camada\Snapshot\MatchInput;
use Camada\Transport\HttpRequest;
use Camada\Transport\HttpResponse;
use PHPUnit\Framework\TestCase;

/**
 * Snapshot\Client: the single-tenant port of the edge collector's snapshot lifecycle over the
 * GET /snapshot contract (200 frame + etag + x-camada-config; 304 unchanged; 204 nothing
 * published -> enforce nothing), file-backed so every PHP worker shares one copy. Cold = fail
 * open; any error keeps the previous snapshot.
 */
final class ClientTest extends TestCase
{
    private const URL = 'https://analyst.test/snapshot';
    private string $dir;

    protected function setUp(): void
    {
        Guarded::useStamp(null);   // each test judges its own log lines
        $this->dir = sys_get_temp_dir() . '/camada-client-' . getmypid() . '-' . random_int(1, 1_000_000);
    }

    protected function tearDown(): void
    {
        foreach (glob($this->dir . '/*') ?: [] as $f) {
            @unlink($f);
        }
        @rmdir($this->dir);
    }

    private function client(FakeAnalyst $a, ?float $refreshS = null, int $snapshotVersion = 5): Client
    {
        return new Client(self::URL, 'snap-test', new Cache($this->dir), $a, sdk: '@camada/php/0.0.0', snapshotVersion: $snapshotVersion, refreshS: $refreshS);
    }

    public function testColdClientFailsOpenAndIsStale(): void
    {
        $c = $this->client(new FakeAnalyst());
        $v = $c->verdict(new MatchInput(ip: FakeAnalyst::BLOCKED_IP));
        self::assertSame('cold', $v->reason);
        self::assertFalse($v->block);
        self::assertFalse($v->challenge);
        self::assertFalse($v->allowed);
        self::assertTrue($c->stale());
        self::assertNull($c->config());
    }

    public function testLoadsAndEnforcesWithTheContractHeaders(): void
    {
        $a = new FakeAnalyst();
        $c = $this->client($a);
        $c->refresh();
        self::assertTrue($c->verdict(new MatchInput(ip: FakeAnalyst::BLOCKED_IP))->block);
        self::assertFalse($c->stale());
        $req = $a->snapshotRequests[0];
        self::assertSame('Bearer snap-test', $req->headers['authorization']);
        self::assertSame('@camada/php/0.0.0', $req->headers['x-camada-sdk']);
        self::assertSame('5', $req->headers['x-camada-snapshot']);
        self::assertSame('gzip', $req->headers['accept-encoding']);
        self::assertArrayNotHasKey('if-none-match', $req->headers);
        self::assertSame($a->config, $c->config());
        self::assertFileExists($this->dir . '/snapshot.bin');
        self::assertFileExists($this->dir . '/snapshot.meta.json');
        self::assertSame($a->binary(), file_get_contents($this->dir . '/snapshot.bin'));   // the raw BLK container only
    }

    public function testAFreshClientOverTheSameCacheReadsWhatAnotherWrote(): void
    {
        // what PHP-FPM does: worker A refreshes, worker B (a new process, a new Client) enforces from disk
        $a = new FakeAnalyst();
        $this->client($a)->refresh();
        $other = $this->client(new FakeAnalyst());   // its own transport is never used
        self::assertTrue($other->verdict(new MatchInput(ip: FakeAnalyst::BLOCKED_IP))->block);
        self::assertSame('ip4', $other->verdict(new MatchInput(ip: FakeAnalyst::BLOCKED_IP))->reason);
        self::assertFalse($other->stale());
        self::assertSame($a->config, $other->config());
    }

    public function test304RepeatsConfigAndKeepsTheSnapshot(): void
    {
        $a = new FakeAnalyst();
        $c = $this->client($a);
        $c->refresh();
        $a->config = ['beacon' => false] + $a->config;
        $c->refresh();
        self::assertSame($a->etag(), $a->snapshotRequests[1]->headers['if-none-match']);
        self::assertTrue($c->verdict(new MatchInput(ip: FakeAnalyst::BLOCKED_IP))->block);
        self::assertFalse($c->config()['beacon'] ?? null);
    }

    public function test204MeansNothingPublishedAndNotCold(): void
    {
        $a = new FakeAnalyst();
        $c = $this->client($a);
        $c->refresh();
        $a->snapshotStatus = 204;
        $c->refresh();
        $v = $c->verdict(new MatchInput(ip: FakeAnalyst::BLOCKED_IP));
        self::assertNull($v->reason);
        self::assertFalse($v->block);
        self::assertFileDoesNotExist($this->dir . '/snapshot.bin');
        self::assertFalse($c->stale());
    }

    public function testErrorsKeepWhatWeHave(): void
    {
        $a = new FakeAnalyst();
        $c = $this->client($a);
        $c->refresh();
        foreach ([401, 500] as $status) {
            $a->snapshotStatus = $status;
            $c->refresh();
            self::assertTrue($c->verdict(new MatchInput(ip: FakeAnalyst::BLOCKED_IP))->block);
        }
        $a->snapshotStatus = null;
        $a->snapshotDown = true;
        $c->refresh();
        self::assertTrue($c->verdict(new MatchInput(ip: FakeAnalyst::BLOCKED_IP))->block);
    }

    public function testCorruptBodyKeepsThePreviousSnapshot(): void
    {
        $a = new FakeAnalyst();
        $c = $this->client($a);
        $c->refresh();
        $a->tamper = static fn (HttpRequest $req, HttpResponse $r): HttpResponse => new HttpResponse(200, ['etag' => '"other"'] + $r->headers, "\x05\x00\x00\x00junk!" . str_repeat("\x00", 10));
        $prev = ini_set('error_log', $this->dir . '/error.log');
        try {
            $c->refresh();
        } finally {
            ini_set('error_log', $prev === false ? '' : $prev);
        }
        self::assertTrue($c->verdict(new MatchInput(ip: FakeAnalyst::BLOCKED_IP))->block);
        self::assertSame($a->binary(), file_get_contents($this->dir . '/snapshot.bin'));
    }

    public function testSameVersionNewEtagReparses(): void
    {
        // the server ships v3/v4/v5 bodies of one publish under the same meta.version and different etags
        $a = new FakeAnalyst();
        $c = $this->client($a);
        $c->refresh();
        self::assertFalse($c->verdict(new MatchInput(ip: FakeAnalyst::CHALLENGED_IP))->challenge);   // v3 has no challenge side
        $a->container = 'v4';
        $c->refresh();
        self::assertTrue($c->verdict(new MatchInput(ip: FakeAnalyst::CHALLENGED_IP))->challenge);
    }

    public function testSnapshotVersionHeaderFollowsTheOption(): void
    {
        $a = new FakeAnalyst();
        $this->client($a, snapshotVersion: 4)->refresh();
        $this->client($a, snapshotVersion: 3)->refresh();
        self::assertSame(['4', ''], $a->snapshotVersions);
    }

    public function testServerSteersTheCadenceUnlessPinned(): void
    {
        $a = new FakeAnalyst();
        $a->config = ['poll_seconds' => 7] + $a->config;
        $c = $this->client($a);
        self::assertSame(30.0, $c->refreshS());
        $c->refresh();
        self::assertSame(7.0, $c->refreshS());
        $a->config = ['poll_seconds' => 1] + $a->config;   // below the 5 s floor: ignored
        $c->refresh();
        self::assertSame(7.0, $c->refreshS());
        $a->config = ['poll_seconds' => 'NaN'] + $a->config;   // not a number: ignored
        $c->refresh();
        self::assertSame(7.0, $c->refreshS());
        $pinned = $this->client($a, refreshS: 11.0);
        $pinned->refresh();
        self::assertSame(11.0, $pinned->refreshS());
    }

    public function testNonFinitePollSecondsIsIgnored(): void
    {
        $a = new FakeAnalyst();
        $a->config['poll_seconds'] = 1e999;   // json_encode writes it as... nothing PHP can read back finitely
        $c = $this->client($a);
        $c->refresh();
        self::assertSame(30.0, $c->refreshS());
    }

    public function testStaleAtNinetyPercentOfTheCadence(): void
    {
        $a = new FakeAnalyst();
        $c = $this->client($a);
        $c->refresh();
        self::assertFalse($c->stale());
        $cache = new Cache($this->dir);
        $state = $cache->readJson('state.json');
        self::assertNotNull($state);
        $state['loaded_at'] = microtime(true) - 26;   // 0.9 x 30 = 27: not yet
        $cache->writeJson('state.json', $state);
        self::assertFalse($this->client($a)->stale());
        $state['loaded_at'] = microtime(true) - 28;
        $cache->writeJson('state.json', $state);
        self::assertTrue($this->client($a)->stale());
    }

    public function testRefreshIsSingleInFlightAcrossProcesses(): void
    {
        $a = new FakeAnalyst();
        $c = $this->client($a);
        new Cache($this->dir);
        $held = Lock::tryAcquire($this->dir . '/refresh.lock');   // another worker is mid-poll
        self::assertNotNull($held);
        $c->refresh();
        self::assertSame([], $a->snapshotRequests);   // yielded without a request
        $held->release();
        $c->refresh();
        self::assertCount(1, $a->snapshotRequests);
    }

    public function testATornStateFileIsCold(): void
    {
        $a = new FakeAnalyst();
        $c = $this->client($a);
        $c->refresh();
        file_put_contents($this->dir . '/state.json', '{"etag": "x", "loaded_at": 1');   // never happens (tmp + rename), but must not throw
        self::assertSame('cold', $this->client($a)->verdict(new MatchInput(ip: FakeAnalyst::BLOCKED_IP))->reason);
    }
}
