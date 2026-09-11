<?php

declare(strict_types=1);

namespace Camada\Tests;

use Camada\Runtime\Cache;
use Camada\Runtime\Deferred;
use Camada\Runtime\Lock;
use PHPUnit\Framework\TestCase;

/**
 * The file-backed runtime one request hands the next: atomic writes (tmp + rename, never a torn
 * file), non-blocking locks, and the post-response phase's fixed order.
 */
final class RuntimeTest extends TestCase
{
    private string $dir;

    protected function setUp(): void
    {
        $this->dir = sys_get_temp_dir() . '/camada-rt-' . getmypid() . '-' . random_int(1, 1_000_000);
    }

    protected function tearDown(): void
    {
        foreach (glob($this->dir . '/*') ?: [] as $f) {
            @unlink($f);
        }
        @rmdir($this->dir);
    }

    public function testCacheCreatesItsDirAndWritesAtomically(): void
    {
        $c = new Cache($this->dir);
        self::assertDirectoryExists($this->dir);
        self::assertNull($c->read('state.json'));
        self::assertFalse($c->exists('state.json'));
        $c->write('snapshot.bin', "\x01\x02");
        self::assertSame("\x01\x02", $c->read('snapshot.bin'));
        $c->writeJson('state.json', ['etag' => '"a"', 'none' => false]);
        self::assertSame(['etag' => '"a"', 'none' => false], $c->readJson('state.json'));
        self::assertSame([$this->dir . '/snapshot.bin', $this->dir . '/state.json'], glob($this->dir . '/*'));   // no tmp files left behind
        $c->unlink('snapshot.bin');
        self::assertFalse($c->exists('snapshot.bin'));
        $c->unlink('snapshot.bin');   // idempotent
        self::assertSame($this->dir . '/x', $c->path('x'));
    }

    public function testCacheReadsJunkJsonAsNothing(): void
    {
        $c = new Cache($this->dir);
        $c->write('state.json', '{not json');
        self::assertNull($c->readJson('state.json'));
        $c->write('state.json', '[1,2]');
        self::assertNull($c->readJson('state.json'));   // a list is not the state object
    }

    public function testCacheDefaultDirIsKeyedByTheSnapshotToken(): void
    {
        $a = Cache::defaultDir('snap-a');
        self::assertSame(sys_get_temp_dir() . '/camada-' . substr(hash('sha256', 'snap-a'), 0, 16), $a);
        self::assertNotSame($a, Cache::defaultDir('snap-b'));
        self::assertSame('/x/y', Cache::defaultDir('snap-a', '/x/y/'));   // CAMADA_CACHE_DIR wins, trailing slash dropped
    }

    public function testLockIsNonBlockingAndReleases(): void
    {
        $path = $this->dir . '/refresh.lock';
        mkdir($this->dir);
        $a = Lock::tryAcquire($path);
        self::assertNotNull($a);
        self::assertNull(Lock::tryAcquire($path));   // held: the second caller yields at once
        $a->release();
        $b = Lock::tryAcquire($path);
        self::assertNotNull($b);
        $b->release();
        $b->release();   // idempotent
        self::assertNull(Lock::tryAcquire($this->dir . '/no/such/dir/x.lock'));   // an unwritable path is "not acquired", never a throw
    }

    public function testDeferredRunsFinishThenShipThenRefreshOnce(): void
    {
        $d = new Deferred();
        $order = [];
        $d->arm(Deferred::REFRESH, static function () use (&$order): void {
            $order[] = 'refresh';
        });
        $d->arm(Deferred::SHIP, static function () use (&$order): void {
            $order[] = 'ship';
        });
        $d->arm(Deferred::FINISH, static function () use (&$order): void {
            $order[] = 'finish';
        });
        $d->arm(Deferred::REFRESH, static function () use (&$order): void {
            $order[] = 'refresh-again';   // armed twice: the first wins
        });
        self::assertTrue($d->armed(Deferred::REFRESH));
        $d->runTasks();
        self::assertSame(['finish', 'ship', 'refresh'], $order);
        $d->runTasks();   // nothing left: a second run is a no-op
        self::assertSame(['finish', 'ship', 'refresh'], $order);
        self::assertFalse($d->armed(Deferred::REFRESH));
    }

    public function testDeferredKeepsGoingWhenATaskThrows(): void
    {
        $d = new Deferred();
        $ran = false;
        $d->arm(Deferred::FINISH, static function (): void {
            throw new \RuntimeException('sdk bug');
        });
        $d->arm(Deferred::SHIP, static function () use (&$ran): void {
            $ran = true;
        });
        $prev = ini_set('error_log', $this->dir . '.log');
        try {
            $d->runTasks();
        } finally {
            ini_set('error_log', $prev === false ? '' : $prev);
            @unlink($this->dir . '.log');
        }
        self::assertTrue($ran);
    }

    public function testDeferredInstallsTheShutdownHookOnce(): void
    {
        $d = new Deferred(register: false);   // the real one registers register_shutdown_function; the test only checks the latch
        self::assertFalse($d->installed());
        $d->install();
        $d->install();
        self::assertTrue($d->installed());
    }
}
