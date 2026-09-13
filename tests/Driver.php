<?php

declare(strict_types=1);

namespace Camada\Tests;

use Camada\Answer;
use Camada\Camada;
use Camada\Context;
use Camada\Req;
use Camada\Snapshot\MatchInput;

/**
 * Drives the engine through the adapter seam without a server, the way an adapter does:
 * wantsBody -> handle -> the app -> onFinish -> the post-response phase. The engine suite runs
 * on it; host-specific behaviour lives in SapiTest (php -S) and LaravelTest.
 */
final class Driver
{
    public const ENV = ['CAMADA_KEY' => 'tok-test.snap-test', 'CAMADA_INGEST_URL' => 'https://analyst.test'];

    /** @var list<Context> */
    public array $seen = [];
    /** @var \Closure(Context): array{int, list<array{string, string}>, string} */
    private \Closure $handler;

    /** @param (\Closure(Context): array{int, list<array{string, string}>, string})|null $handler */
    public function __construct(public readonly Camada $engine, ?\Closure $handler = null)
    {
        $this->handler = $handler ?? static fn (Context $ctx): array => [200, [['content-type', 'text/plain']], 'hello'];
    }

    /**
     * @param array<string, mixed> $env
     */
    public static function engineWith(FakeAnalyst $a, string $cacheDir, array $env = [], mixed ...$opts): Camada
    {
        /** @var array<string, mixed> $opts */
        return new Camada(...['env' => array_merge(self::ENV, ['CAMADA_CACHE_DIR' => $cacheDir], $env), 'transport' => $a, ...$opts]);
    }

    public static function loaded(Camada $engine): void
    {
        if ($engine->snap === null) {
            throw new \LogicException('no snapshot client');
        }
        $engine->snap->refresh();
        if ($engine->snap->verdict(new MatchInput(ip: '0.0.0.0'))->reason === 'cold') {
            throw new \LogicException('snapshot never loaded');
        }
    }

    public function __invoke(Call $c): Reply
    {
        $q = strpos($c->path, '?');
        $path = $q === false ? $c->path : substr($c->path, 0, $q);
        $query = $q === false ? '' : substr($c->path, $q);
        $headers = [];
        $hasHost = false;
        foreach ($c->headers as [$k, $v]) {
            $headers[] = [strtolower($k), $v];
            $hasHost = $hasHost || strtolower($k) === 'host';
        }
        if (!$hasHost) {
            $headers[] = ['host', 'x.test'];
        }
        if ($c->method === 'POST' || $c->method === 'PUT' || $c->body !== '') {
            $headers[] = ['content-length', (string) ($c->contentLength ?? strlen($c->body))];
        }
        $req = new Req(method: $c->method, path: $path, query: $query, host: 'x.test', httpVersion: '1.1', peer: $c->peer, https: $c->https, headers: $headers);
        $limit = $this->engine->wantsBody($req->method, $req->path);
        $body = null;
        if ($limit !== null) {
            $declared = $c->contentLength ?? strlen($c->body);
            $body = $declared > $limit || strlen($c->body) > $limit ? null : $c->body;
        }
        $r = $this->engine->handle($req, $body);
        if ($r instanceof Answer) {
            $this->engine->deferred()->runTasks();
            return new Reply($r->status, [...$r->headers, ['content-length', (string) strlen($r->body)]], $r->body);
        }
        $ctx = $r->ctx ?? Context::inert();
        $this->seen[] = $ctx;
        try {
            [$status, $appHeaders, $out] = ($this->handler)($ctx);
        } catch (\Throwable $e) {
            if ($r->onFinish !== null) {
                ($r->onFinish)(500);   // the app threw: the server will answer 500
            }
            $this->engine->deferred()->runTasks();
            throw $e;
        }
        if ($r->rid !== null) {
            $appHeaders[] = ['x-rid', $r->rid];
        }
        if ($r->setCookie !== null) {
            $appHeaders[] = ['set-cookie', $r->setCookie];
        }
        if ($r->onFinish !== null) {
            ($r->onFinish)($status);
        }
        $this->engine->deferred()->runTasks();
        return new Reply($status, $appHeaders, $out);
    }
}

final class Call
{
    /** @param list<array{string, string}> $headers */
    public function __construct(
        public readonly string $method = 'GET',
        public readonly string $path = '/',
        public readonly array $headers = [],
        public readonly string $body = '',
        public readonly ?string $peer = '172.16.0.9',   // a peer no golden container lists (10.0.0.0/8 is blocked in all of them)
        public readonly bool $https = false,
        public readonly ?int $contentLength = null,      // override the declared length (null = actual)
    ) {
    }
}

final class Reply
{
    /** @param list<array{string, string}> $headers */
    public function __construct(public readonly int $status, public readonly array $headers, public readonly string $body)
    {
    }

    public function header(string $name): ?string
    {
        foreach ($this->headers as [$k, $v]) {
            if (strtolower($k) === $name) {
                return $v;
            }
        }
        return null;
    }

    /** @return list<string> */
    public function headersNamed(string $name): array
    {
        $out = [];
        foreach ($this->headers as [$k, $v]) {
            if (strtolower($k) === $name) {
                $out[] = $v;
            }
        }
        return $out;
    }
}
