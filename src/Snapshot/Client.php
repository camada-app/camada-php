<?php

declare(strict_types=1);

namespace Camada\Snapshot;

use Camada\Config;
use Camada\Constants;
use Camada\Guarded;
use Camada\Runtime\Cache;
use Camada\Runtime\Lock;
use Camada\Transport\HttpRequest;
use Camada\Transport\TransportInterface;

/**
 * Snapshot client: the single-tenant port of the edge collector's snapshot lifecycle over the
 * GET /snapshot contract (ported from camada-python's snapshot/client.py):
 *   200  [u32 LE meta-length][meta JSON][BLK container] + etag + x-camada-config
 *   304  nothing changed; config header repeated (config refreshes every poll for free)
 *   204  authenticated, no snapshot published -> enforce nothing, fail open
 * Semantics ported exactly: single in-flight load (refresh.lock, across workers); loaded_at
 * stamped even on 204 (retry per poll cadence, not per request); any error keeps the previous
 * snapshot; cold = fail open.
 *
 * File-backed: state.json {etag, version, loaded_at, refresh_s, config, none} steers every
 * worker, snapshot.bin is the raw container the matcher seeks into, snapshot.meta.json rides
 * beside it. The request path only reads; refresh() is the post-response phase's job.
 *
 * @phpstan-import-type RemoteConfig from Config
 */
final class Client
{
    private const STATE = 'state.json';
    private const BIN = 'snapshot.bin';
    private const META = 'snapshot.meta.json';
    private const LOCK = 'refresh.lock';

    /** @var array<string, mixed>|null */
    private ?array $state = null;
    private bool $stateRead = false;
    private ?Matcher $matcher = null;
    private ?string $matcherKey = null;

    public function __construct(
        public readonly string $url,
        public readonly string $token,
        private readonly Cache $cache,
        private readonly TransportInterface $transport,
        private readonly ?string $sdk = null,          // '<package>/<version>': sent as x-camada-sdk on every poll (SDK-03)
        private readonly int $snapshotVersion = Constants::DEFAULT_SNAPSHOT_VERSION,   // 5 asks for the custom rules too; 4 the sides only; 3 opts out of both
        private readonly ?float $refreshS = null,      // leave unset and the server's poll_seconds steers it; set it and it is pinned
        private readonly float $timeoutS = 3.0,
    ) {
    }

    /** The directory the snapshot, its state and the spool live in (shared by every worker). */
    public function cacheDir(): string
    {
        return $this->cache->dir;
    }

    /** Forget the memoised state: the next read hits the disk (one per request; the adapter calls it at entry). */
    public function invalidate(): void
    {
        $this->stateRead = false;
        $this->state = null;
    }

    /** @return array<string, mixed>|null */
    private function state(): ?array
    {
        if (!$this->stateRead) {
            $this->state = $this->cache->readJson(self::STATE);
            $this->stateRead = true;
        }
        return $this->state;
    }

    /** @return RemoteConfig|null */
    public function config(): ?array
    {
        return Config::remoteConfig($this->state()['config'] ?? null);
    }

    public function refreshS(): float
    {
        if ($this->refreshS !== null) {
            return $this->refreshS;
        }
        $s = $this->state()['refresh_s'] ?? null;
        return is_int($s) || is_float($s) ? (float) $s : Constants::DEFAULT_REFRESH_S;
    }

    /**
     * 0.9 x refresh so a poll landing at ~refresh-ε still counts; a full-interval comparison
     * makes every other one a no-op (effective cadence 2x). Cold (no state) is stale.
     */
    public function stale(): bool
    {
        $loaded = $this->state()['loaded_at'] ?? 0;
        $loaded = is_int($loaded) || is_float($loaded) ? (float) $loaded : 0.0;
        return microtime(true) - $loaded > $this->refreshS() * 0.9;
    }

    /** One synchronous poll, single in-flight across workers; never throws (the post-response phase calls it). */
    public function refresh(): void
    {
        $lock = Lock::tryAcquire($this->cache->path(self::LOCK));
        if ($lock === null) {
            return;
        }
        try {
            $this->invalidate();
            $this->load();
        } catch (\Throwable $err) {   // a poll that can never succeed must not be silent, nor fatal
            Guarded::log($err);
        } finally {
            $lock->release();
            $this->invalidate();
        }
    }

    private function load(): void
    {
        $s = $this->state() ?? [];
        $headers = ['authorization' => "Bearer {$this->token}", 'accept-encoding' => 'gzip'];
        if (is_string($s['etag'] ?? null) && $s['etag'] !== '') {
            $headers['if-none-match'] = $s['etag'];
        }
        if ($this->sdk !== null) {
            $headers['x-camada-sdk'] = $this->sdk;
        }
        if ($this->snapshotVersion > 3) {
            $headers['x-camada-snapshot'] = (string) $this->snapshotVersion;   // a tenant without that container is answered with the next one down
        }
        $res = $this->transport->send(new HttpRequest('GET', $this->url, $headers, null, $this->timeoutS));
        if (!in_array($res->status, [200, 204, 304], true)) {
            if (!(($s['loaded_at'] ?? 0) > 0)) {   // still cold: a snapshot that never arrives (a dead URL, allow_url_fopen=Off, no ext-zlib) must not fail open in silence
                Guarded::log("camada: snapshot poll got status {$res->status} from {$this->url}; enforcing nothing until it succeeds");
            }
            return;   // 401/5xx/network: keep what we have
        }
        $s['loaded_at'] = microtime(true);
        $this->readConfig($s, $res->headers['x-camada-config'] ?? null);
        if ($res->status === 304) {
            $this->cache->writeJson(self::STATE, $s);
            return;
        }
        if ($res->status === 204) {   // no snapshot published: enforce nothing
            $this->cache->unlink(self::BIN);
            $this->cache->unlink(self::META);
            $s['etag'] = null;
            $s['version'] = null;
            $s['none'] = true;
            $this->cache->writeJson(self::STATE, $s);
            return;
        }
        // loaded_at is stamped before the body is judged: a corrupt frame keeps the previous snapshot
        // and retries per poll cadence, not per request (the collector's stance)
        $this->cache->writeJson(self::STATE, $s);
        $body = $res->body;
        if (strlen($body) < 4) {
            throw new \RuntimeException('camada: truncated snapshot frame');
        }
        /** @var array{1: int} $len */
        $len = unpack('V', $body);
        $metaLen = $len[1];
        if (4 + $metaLen > strlen($body)) {
            throw new \RuntimeException('camada: truncated snapshot frame');
        }
        $meta = json_decode(substr($body, 4, $metaLen), true, 512, JSON_THROW_ON_ERROR);
        if (!is_array($meta)) {
            throw new \RuntimeException('camada: snapshot meta is not an object');
        }
        /** @var array<string, mixed> $meta */
        $etag = $res->headers['etag'] ?? null;
        // The server ships the v3, v4 and v5 bodies of one publish under the SAME meta.version and
        // different etags, so version alone cannot say "nothing changed".
        if (($s['none'] ?? false) !== true && $etag !== null && ($s['etag'] ?? null) === $etag && ($s['version'] ?? null) === ($meta['version'] ?? null) && $this->cache->exists(self::BIN)) {
            return;
        }
        $blk = substr($body, 4 + $metaLen);
        Parser::parse(new MemoryWords($blk), $meta);   // throws on corrupt data -> caught by refresh(), previous kept
        $this->cache->write(self::BIN, $blk);
        $this->cache->writeJson(self::META, $meta);
        $s['etag'] = $etag;
        $s['version'] = $meta['version'] ?? null;
        $s['none'] = false;
        $this->cache->writeJson(self::STATE, $s);
    }

    /** @param array<string, mixed> $s */
    private function readConfig(array &$s, ?string $raw): void
    {
        if ($raw === null || $raw === '') {
            return;
        }
        $cfg = Config::remoteConfig(json_decode($raw, true));
        if ($cfg === null) {
            return;   // keep the previous config
        }
        $s['config'] = $cfg;
        // the server steers the poll cadence per tenant (its cost lever) unless the client pinned one
        $secs = $cfg['poll_seconds'] ?? null;
        if ($this->refreshS !== null || !(is_int($secs) || is_float($secs)) || !is_finite($secs) || $secs < 5) {
            return;
        }
        $s['refresh_s'] = (float) $secs;
    }

    /** Cold (never loaded) and no-snapshot both fail open, mirroring the edge collector. */
    public function verdict(MatchInput $i): MatchResult
    {
        $s = $this->state();
        if ($s === null || !(($s['loaded_at'] ?? 0) > 0)) {
            return new MatchResult(reason: 'cold');
        }
        if (($s['none'] ?? false) === true) {
            return new MatchResult();
        }
        $m = $this->matcher($s);
        return $m !== null ? $m->match($i) : new MatchResult();
    }

    /**
     * The matcher over the cached container: opened once per (etag, version), re-opened when
     * another worker's refresh moved the state on. The open handle pins the old inode meanwhile.
     *
     * @param array<string, mixed> $s
     */
    private function matcher(array $s): ?Matcher
    {
        $key = json_encode([$s['etag'] ?? null, $s['version'] ?? null]);
        if ($this->matcher !== null && $this->matcherKey === $key) {
            return $this->matcher;
        }
        try {
            $meta = $this->cache->readJson(self::META) ?? [];
            $this->matcher = new Matcher(Parser::parse(FileWords::open($this->cache->path(self::BIN)), $meta));
            $this->matcherKey = $key === false ? null : $key;
            return $this->matcher;
        } catch (\Throwable $err) {   // a container that vanished or will not parse: fail open, retried next poll
            Guarded::log($err);
            return null;
        }
    }
}
