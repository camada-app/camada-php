<?php

declare(strict_types=1);

namespace Camada\Events;

use Camada\Guarded;
use Camada\Runtime\Cache;
use Camada\Runtime\Lock;
use Camada\Transport\HttpRequest;
use Camada\Transport\TransportInterface;

/**
 * Events\Spool: fire-and-forget batched shipping to POST /e (the file-backed twin of
 * camada-python's events/queue.py). The collector ships one event per request; an in-process
 * SDK batches, and PHP has no process to batch in — so rows are appended to events.ndjson under
 * the spool lock, and the post-response phase of whichever request finds the spool due (≥ 500
 * rows, or 15 s since the last flush) ships it in slices of ≤ 1000 per POST. The same law holds:
 * NOTHING here may ever throw into the request path, and a dead ingest must cost nothing but
 * dropped telemetry. Over the queue cap the appender keeps the newest half (drop-oldest).
 */
final class Spool
{
    private const SPOOL = 'events.ndjson';
    private const LOCK = 'events.lock';
    private const COUNT = 'events.count';
    private const FLUSH = 'flush.json';
    private const ORPHAN_S = 120;   // a .sending file older than this belongs to a worker that died mid-POST

    private readonly string $url;

    public function __construct(
        private readonly Cache $cache,
        private readonly TransportInterface $transport,
        string $url,                                  // ingest base, e.g. https://analyst.example.com
        private readonly string $token,               // ingest token (x-tenant header)
        private readonly ?string $sdk = null,         // '<package>/<version>': sent as x-camada-sdk on every batch (SDK-03)
        private readonly int $maxBatch = 500,         // ship when the spool reaches this many (server caps at 1000)
        private readonly int $maxQueue = 2000,        // drop-oldest beyond this
        private readonly float $flushS = 15.0,
        private readonly float $timeoutS = 2.0,
    ) {
        $this->url = rtrim($url, '/');
    }

    /** Synchronous, never throws: one appended line under the spool lock. */
    public function push(mixed $row): void
    {
        try {
            $line = json_encode($row, JSON_UNESCAPED_SLASHES | JSON_INVALID_UTF8_SUBSTITUTE | JSON_PARTIAL_OUTPUT_ON_ERROR);
            if ($line === false) {
                throw new \RuntimeException('camada: unencodable event');
            }
            $lock = Lock::acquire($this->cache->path(self::LOCK));
            if ($lock === null) {
                throw new \RuntimeException('camada: cannot lock the event spool in ' . $this->cache->dir);
            }
            try {
                if (@file_put_contents($this->cache->path(self::SPOOL), $line . "\n", FILE_APPEND) === false) {
                    throw new \RuntimeException('camada: cannot append to the event spool');
                }
                $n = $this->size() + 1;
                if ($n > $this->maxQueue) {
                    $n = $this->truncate($n);
                }
                $this->cache->write(self::COUNT, (string) $n);
                if (!$this->cache->exists(self::FLUSH)) {
                    $this->stamp(0);   // the first row starts the flush clock, as the queue's flush thread did
                }
            } finally {
                $lock->release();
            }
        } catch (\Throwable $err) {   // never into the request path
            Guarded::log($err);
        }
    }

    /** Under the lock: keep the newest half of the spool, count the rest as dropped. */
    private function truncate(int $n): int
    {
        $lines = file($this->cache->path(self::SPOOL), FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);
        if ($lines === false) {
            return $n;
        }
        $keep = max(1, intdiv($this->maxQueue, 2));
        $kept = array_slice($lines, -$keep);
        $this->cache->write(self::SPOOL, implode("\n", $kept) . "\n");
        $this->stamp(count($lines) - count($kept));
        return count($kept);
    }

    public function dropped(): int
    {
        $d = $this->cache->readJson(self::FLUSH)['dropped'] ?? 0;
        return is_int($d) ? $d : 0;
    }

    public function size(): int
    {
        $c = $this->cache->read(self::COUNT);
        return $c === null || !$this->cache->exists(self::SPOOL) ? 0 : max(0, (int) $c);
    }

    /** Adds to `dropped` and, when $touch, restamps last_flush. Callers hold the lock or accept the tiny race on a debug counter. */
    private function stamp(int $dropped, bool $touch = true): void
    {
        $f = $this->cache->readJson(self::FLUSH) ?? [];
        $prev = $f['dropped'] ?? 0;
        $f['dropped'] = (is_int($prev) ? $prev : 0) + $dropped;
        if ($touch) {
            $f['last_flush'] = microtime(true);
        }
        $this->cache->writeJson(self::FLUSH, $f);
    }

    /** ≥ maxBatch rows, or flushS since the last flush — and something to ship. */
    public function due(): bool
    {
        $n = $this->size();
        if ($n <= 0) {
            return false;
        }
        if ($n >= $this->maxBatch) {
            return true;
        }
        $last = $this->cache->readJson(self::FLUSH)['last_flush'] ?? 0;
        $last = is_int($last) || is_float($last) ? (float) $last : 0.0;
        return microtime(true) - $last >= $this->flushS;
    }

    public function shipIfDue(): void
    {
        if ($this->due()) {
            $this->flush();
        }
    }

    /**
     * Ships the spool now, if no other worker is on it: under the lock the spool is renamed to
     * a private .sending file and the flush clock restamped, then — lock released, so appends
     * never wait on the network — POSTed in slices of ≤ 1000. Orphans of a crashed worker ride
     * along. Never throws.
     */
    public function flush(): void
    {
        try {
            $lock = Lock::tryAcquire($this->cache->path(self::LOCK));
            if ($lock === null) {
                return;   // another worker is shipping: yield
            }
            $files = [];
            try {
                if ($this->cache->exists(self::SPOOL)) {
                    $sending = 'events.' . getmypid() . '.' . bin2hex(random_bytes(3)) . '.sending';
                    if (@rename($this->cache->path(self::SPOOL), $this->cache->path($sending))) {
                        $files[] = $sending;
                    }
                    $this->cache->write(self::COUNT, '0');
                }
                $this->stamp(0);
                foreach (glob($this->cache->path('events.*.sending')) ?: [] as $orphan) {
                    $name = basename($orphan);
                    $m = @filemtime($orphan);
                    if (!in_array($name, $files, true) && $m !== false && time() - $m > self::ORPHAN_S) {
                        $files[] = $name;
                    }
                }
            } finally {
                $lock->release();
            }
            foreach ($files as $name) {
                $this->ship($name);
            }
        } catch (\Throwable $err) {
            Guarded::log($err);
        }
    }

    private function ship(string $name): void
    {
        $path = $this->cache->path($name);
        $rows = [];
        foreach (file($path, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES) ?: [] as $line) {
            $row = json_decode($line, true);
            if (is_array($row)) {
                $rows[] = $row;
            }
        }
        @unlink($path);
        $headers = ['x-tenant' => $this->token, 'content-type' => 'application/json'];
        if ($this->sdk !== null) {
            $headers['x-camada-sdk'] = $this->sdk;
        }
        foreach (array_chunk($rows, 1000) as $batch) {
            try {
                $body = json_encode($batch, JSON_THROW_ON_ERROR | JSON_UNESCAPED_SLASHES | JSON_INVALID_UTF8_SUBSTITUTE);
                $res = $this->transport->send(new HttpRequest('POST', "{$this->url}/e", $headers, $body, $this->timeoutS));
                if ($res->status === 0) {
                    throw new \RuntimeException('ingest unreachable');
                }
            } catch (\Throwable $err) {
                // Dropping telemetry is by design, doing it silently is not: a mount that can never
                // reach ingest looks identical to a healthy one otherwise.
                $this->stamp(count($batch), touch: false);
                Guarded::log($err);
            }
        }
    }
}
