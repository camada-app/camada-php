<?php

declare(strict_types=1);

namespace Camada\Tests;

use Camada\Transport\HttpRequest;
use Camada\Transport\HttpResponse;
use Camada\Transport\TransportInterface;

/**
 * An in-process transport standing in for the analyst Worker (GET /snapshot, POST /e): the
 * PHP twin of camada-python's tests/fake_analyst.py.
 */
final class FakeAnalyst implements TransportInterface
{
    public const BLOCKED_IP = '203.0.113.66';      // an ip4 entry in v3-basic and v4-basic
    public const CHALLENGED_IP = '192.0.2.20';     // a challenge-only ip4 entry in v4-basic
    public const ALLOWED_IP = '10.0.0.7';          // allow-listed inside the blocked 10.0.0.0/8
    // v5-rules only (§D3): the ordered custom rules the golden container carries.
    public const RULE_BLOCKED_IP = '198.51.100.7';         // builtin:block, a manual-block entry
    public const SKIP_PATH = '/healthz';                   // cr_00000000000a, skip — beats every side
    public const RULE_BLOCKED_PATH = '/api/v2/dump';       // cr_00000000000c, block by path regex
    public const WARN_UA = 'Scrapy/2.11 (+https://scrapy.org)';   // cr_00000000000e, warn
    public const BLOCKED_UA = 'curl/8.4.0';                // cr_00000000000f, block
    public const BLOCKED_HEADER = 'x-api-key';             // cr_000000000019, `header is` -> block
    public const BLOCKED_HEADER_VALUE = 'leaked-key-1';

    private const META_FILES = ['v3' => 'blk3/v3-basic.meta.json', 'v4' => 'blk3/v4-basic.meta.json', 'v5' => 'blk5/v5-rules.meta.json'];
    private const BIN_FILES = ['v3' => 'blk3/v3-basic.bin', 'v4' => 'blk3/v4-basic.bin', 'v5' => 'blk5/v5-rules.bin'];

    /** @var list<list<array<string, mixed>>> batches POSTed to /e */
    public array $events = [];
    /** @var list<string> x-camada-sdk seen on /snapshot and /e */
    public array $sdkHeaders = [];
    /** @var list<string> x-camada-snapshot seen on /snapshot */
    public array $snapshotVersions = [];
    /** @var list<HttpRequest> */
    public array $snapshotRequests = [];
    /** @var array<string, mixed> */
    public array $config = ['tenant' => 'acme', 'beacon' => true, 'sample' => 1, 'exclude' => [], 'trusted_proxy' => ['mode' => 'none'], 'poll_seconds' => 30];
    public bool $snapshotDown = false;
    public bool $ingestDown = false;
    public ?int $snapshotStatus = null;   // force a status (204, 304, 401, 500)
    public string $container = 'v3';      // v3 | v4 | v5
    public bool $gzip = false;            // gzip the frame when the client asks for it
    public int $ingestStatus = 202;
    /** @var (\Closure(HttpRequest, HttpResponse): HttpResponse)|null a hook over the answer (tests corrupt bodies with it) */
    public ?\Closure $tamper = null;

    /** @return array<string, mixed> */
    public function meta(): array
    {
        return Fixtures::json(self::META_FILES[$this->container]);
    }

    public function binary(): string
    {
        return Fixtures::bin(self::BIN_FILES[$this->container]);
    }

    public function etag(): string
    {
        $suffix = ['v3' => '', 'v4' => '-v4', 'v5' => '-v5'][$this->container];
        return '"' . $this->meta()['version'] . $suffix . '"';
    }

    /** @param array<string, mixed> $meta */
    public static function frame(array $meta, string $body): string
    {
        $m = (string) json_encode($meta);
        return pack('V', strlen($m)) . $m . $body;
    }

    public function send(HttpRequest $req): HttpResponse
    {
        $res = $this->answer($req);
        return $this->tamper !== null ? ($this->tamper)($req, $res) : $res;
    }

    private function answer(HttpRequest $req): HttpResponse
    {
        if (str_ends_with($req->url, '/snapshot') || str_ends_with($req->url, '/e')) {
            $this->sdkHeaders[] = $req->headers['x-camada-sdk'] ?? '';
        }
        if (str_ends_with($req->url, '/snapshot')) {
            $this->snapshotRequests[] = $req;
            $this->snapshotVersions[] = $req->headers['x-camada-snapshot'] ?? '';
            if ($this->snapshotDown) {
                return new HttpResponse(0, [], '');
            }
            $headers = ['x-camada-config' => (string) json_encode($this->config), 'cache-control' => 'private, no-store'];
            if ($this->snapshotStatus !== null) {
                return new HttpResponse($this->snapshotStatus, $headers, '');
            }
            if (($req->headers['if-none-match'] ?? null) === $this->etag()) {
                return new HttpResponse(304, $headers, '');
            }
            $body = self::frame($this->meta(), $this->binary());
            $headers['etag'] = $this->etag();
            if ($this->gzip && str_contains($req->headers['accept-encoding'] ?? '', 'gzip')) {
                $headers['content-encoding'] = 'gzip';
                $body = (string) gzencode($body);
            }
            return new HttpResponse(200, $headers, $body);
        }
        if ($this->ingestDown) {
            return new HttpResponse(0, [], '');
        }
        if (str_ends_with($req->url, '/e')) {
            /** @var list<array<string, mixed>> $batch */
            $batch = json_decode($req->body ?? '[]', true, 512, JSON_THROW_ON_ERROR);
            $this->events[] = $batch;
            return new HttpResponse($this->ingestStatus, [], '');
        }
        throw new \LogicException('unmocked request: ' . $req->url);
    }

    /** @return list<array<string, mixed>> */
    public function allEvents(): array
    {
        return array_merge(...$this->events, ...[[]]);
    }
}
