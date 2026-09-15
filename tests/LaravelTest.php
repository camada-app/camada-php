<?php

declare(strict_types=1);

namespace Camada\Tests;

use Camada\Camada;
use Camada\Context;
use Camada\Guarded;
use Camada\Laravel\Middleware;
use Camada\Runtime\Cache;
use Illuminate\Http\Request;
use Illuminate\Http\Response;
use PHPUnit\Framework\TestCase;

/**
 * The Laravel middleware: handle() runs the engine before the app and stamps the response,
 * terminate() is the post-response phase (Response::send() has already ended the response
 * under FPM). Driven with Illuminate's own Request/Response, no kernel.
 */
final class LaravelTest extends TestCase
{
    /** @var list<string> */
    private array $dirs = [];
    private FakeAnalyst $a;

    protected function setUp(): void
    {
        Guarded::useStamp(null);
        $this->a = new FakeAnalyst();
        $this->a->container = 'v4';
    }

    protected function tearDown(): void
    {
        Camada::setDefault(null);
        foreach ($this->dirs as $d) {
            foreach (glob($d . '/*') ?: [] as $f) {
                @unlink($f);
            }
            @rmdir($d);
        }
    }

    /** @param array<string, mixed> $env */
    private function engine(array $env = []): Camada
    {
        $d = sys_get_temp_dir() . '/camada-laravel-' . getmypid() . '-' . random_int(1, 1_000_000);
        $this->dirs[] = $d;
        $e = Driver::engineWith($this->a, $d, $env);
        Driver::loaded($e);
        return $e;
    }

    /**
     * @param array<string, string> $headers
     * @param array<string, string> $server
     */
    private static function request(string $method, string $uri, array $headers = [], array $server = [], ?string $content = null): Request
    {
        $srv = $server + ['REMOTE_ADDR' => '172.16.0.9', 'SERVER_PROTOCOL' => 'HTTP/1.1', 'HTTP_HOST' => 'x.test'];
        foreach ($headers as $k => $v) {
            $srv['HTTP_' . strtoupper(str_replace('-', '_', $k))] = $v;
        }
        return Request::create($uri, $method, [], [], [], $srv, $content);
    }

    /**
     * @return list<array<string, mixed>>
     * @phpstan-impure
     */
    private function events(Camada $e): array
    {
        $e->spool?->flush();
        return $this->a->allEvents();
    }

    public function testBlocksBeforeTheApp(): void
    {
        $mw = new Middleware($this->engine());
        $ran = false;
        $req = self::request('GET', '/admin?x=1', [], ['REMOTE_ADDR' => FakeAnalyst::BLOCKED_IP]);
        $res = $mw->handle($req, static function () use (&$ran): Response {
            $ran = true;
            return new Response('app');
        });
        self::assertFalse($ran);
        self::assertSame(403, $res->getStatusCode());
        self::assertSame('Forbidden', $res->getContent());
        self::assertSame('ip4', $res->headers->get('x-block-reason'));
        self::assertSame('text/plain', $res->headers->get('content-type'));
        $res->prepare($req);   // what Response::send() runs first: Symfony suffixes the charset the SAPI adapter's bare text/plain omits
        self::assertSame('text/plain; charset=utf-8', strtolower((string) $res->headers->get('content-type')));   // UTF-8 or utf-8 by Symfony version
    }

    public function testAnAnswerOpensNoSocketBeforeTerminate(): void
    {
        // a due spool and a stale snapshot: the 403 is returned first, SHIP and REFRESH ride terminate()
        $e = $this->engine();
        $mw = new Middleware($e);
        $cache = new Cache($this->dirs[0]);
        $state = $cache->readJson('state.json') ?? [];
        $state['loaded_at'] = microtime(true) - 3600;
        $cache->writeJson('state.json', $state);
        $e->spool?->push(['tap' => 'sdk-php', 'st' => 200]);
        $cache->writeJson('flush.json', ['last_flush' => microtime(true) - 20, 'dropped' => 0]);
        $polls = count($this->a->snapshotRequests);
        $req = self::request('GET', '/admin', [], ['REMOTE_ADDR' => FakeAnalyst::BLOCKED_IP]);
        $res = $mw->handle($req, static fn (Request $r): Response => new Response('app'));
        self::assertSame(403, $res->getStatusCode());
        self::assertSame([], $this->a->events);
        self::assertCount($polls, $this->a->snapshotRequests);
        $mw->terminate($req, $res);
        self::assertCount(1, $this->a->events);
        self::assertSame([200, 403], array_column($this->a->events[0], 'st'));
        self::assertCount($polls + 1, $this->a->snapshotRequests);
    }

    public function testTerminateOnAFreshInstanceRunsTheHandlingEngine(): void
    {
        // the kernel resolves the instance it calls terminate() on anew: the engine rides the request,
        // so the due spool ships from the engine that handled it, not from Camada::default()
        $e = $this->engine();
        Camada::setDefault(new Camada(env: ['CAMADA_KEY' => ''], transport: $this->a));
        $req = self::request('GET', '/things');
        $res = (new Middleware($e))->handle($req, static fn (Request $r): Response => new Response('app'));
        (new Cache($this->dirs[0]))->writeJson('flush.json', ['last_flush' => microtime(true) - 20, 'dropped' => 0]);
        (new Middleware())->terminate($req, $res);
        self::assertCount(1, $this->a->events);
        self::assertSame(['/things'], array_column($this->a->events[0], 'p'));
    }

    public function testStampsTheResponseAndShipsOnTerminate(): void
    {
        $e = $this->engine();
        $mw = new Middleware($e);
        $req = self::request('GET', '/things?q=1', ['user-agent' => 'UA/1', 'cookie' => 'a=1']);
        $res = $mw->handle($req, static fn (Request $r): Response => new Response('made', 201, ['x-app' => '1']));
        self::assertSame(201, $res->getStatusCode());
        $rid = $res->headers->get('x-rid');
        self::assertNotNull($rid);
        self::assertSame(36, strlen($rid));
        self::assertStringStartsWith('_sfp=', (string) $res->headers->get('set-cookie'));
        $ctx = $req->attributes->get('camada');
        self::assertInstanceOf(Context::class, $ctx);
        self::assertSame($rid, $ctx->rid);
        self::assertSame('172.16.0.9', $ctx->ip);
        self::assertSame([], $this->events($e));   // nothing before terminate
        $mw->terminate($req, $res);
        [$ev] = $this->events($e);
        self::assertSame(201, $ev['st']);
        self::assertSame($rid, $ev['rid']);
        self::assertSame('/things', $ev['p']);
        self::assertSame('?q=1', $ev['q']);
        self::assertSame('UA/1', $ev['ua']);
        self::assertSame(1, $ev['ck']);
        self::assertSame('x.test', $ev['h']);
        self::assertSame('HTTP/1.1', $ev['proto']);
        $mw->terminate($req, $res);   // idempotent: one request, one event
        self::assertCount(1, $this->events($e));
    }

    public function testTheBeaconAndTheChallengeAnswerFromTheMiddleware(): void
    {
        $e = $this->engine(['CAMADA_TRUSTED_PROXY' => 'hops:1']);
        $mw = new Middleware($e);
        $next = static fn (Request $r): Response => new Response('app');
        $js = $mw->handle(self::request('GET', '/_cam/b.js'), $next);
        self::assertSame('application/javascript', $js->headers->get('content-type'));
        self::assertStringContainsString('@camada/browser', (string) $js->getContent());
        $fp = $mw->handle(self::request('POST', '/_cam/fp', ['content-type' => 'application/json', 'x-forwarded-for' => '198.18.0.5'], [], '{"rid":"r-1"}'), $next);
        self::assertSame(204, $fp->getStatusCode());
        $page = $mw->handle(self::request('GET', '/account', ['accept' => 'text/html', 'sec-fetch-dest' => 'document', 'x-forwarded-for' => FakeAnalyst::CHALLENGED_IP]), $next);
        self::assertSame(403, $page->getStatusCode());
        self::assertSame('1', $page->headers->get('x-camada-challenge'));
        $nonce = explode('"', explode('name="nonce" value="', (string) $page->getContent())[1])[0];
        $form = "nonce={$nonce}&solution=" . ChallengeTest::solve($nonce) . '&to=%2Faccount';
        $ok = $mw->handle(self::request('POST', '/__camada/challenge', ['content-type' => 'application/x-www-form-urlencoded', 'x-forwarded-for' => FakeAnalyst::CHALLENGED_IP], [], $form), $next);
        self::assertSame(302, $ok->getStatusCode());
        self::assertSame('/account', $ok->headers->get('location'));
        self::assertStringStartsWith('_cch=', (string) $ok->headers->get('set-cookie'));
        $sig = array_values(array_filter($this->events($e), static fn (array $r): bool => isset($r['sig'])))[0];
        self::assertSame(1, $sig['sig']);
        self::assertSame('198.18.0.5', $sig['ip']);
    }

    public function testAnOversizedBeaconPostIs413AndAnAppExceptionShips500(): void
    {
        $e = $this->engine();
        $mw = new Middleware($e);
        $big = $mw->handle(self::request('POST', '/_cam/fp', ['content-type' => 'application/json'], [], str_repeat('x', 40000)), static fn (Request $r): Response => new Response('app'));
        self::assertSame(413, $big->getStatusCode());
        $req = self::request('GET', '/crash');
        try {
            $mw->handle($req, static function (Request $r): Response {
                throw new \RuntimeException('app bug');
            });
            self::fail('must propagate');
        } catch (\RuntimeException $x) {
            self::assertSame('app bug', $x->getMessage());
        }
        $evs = $this->events($e);
        self::assertSame(500, $evs[count($evs) - 1]['st']);
        self::assertSame('/crash', $evs[count($evs) - 1]['p']);
    }

    public function testHelpersOnTheRequest(): void
    {
        $e = $this->engine();
        $mw = new Middleware($e);
        $req = self::request('POST', '/login');
        $res = $mw->handle($req, static function (Request $r) use ($e): Response {
            $ctx = $r->attributes->get('camada');
            self::assertInstanceOf(Context::class, $ctx);
            $e->track($ctx, 'login_failed', 'alice@example.com');
            self::assertStringStartsWith('<script src="/_cam/b.js?r=', $e->scriptTag($ctx));
            self::assertSame(403, $e->serveChallenge($ctx)?->status);   // on demand: the page, whatever the verdict says
            return new Response('nope', 401);
        });
        $mw->terminate($req, $res);
        $rows = $this->events($e);
        self::assertCount(2, $rows);
        self::assertSame('login_failed', array_values(array_filter($rows, static fn (array $r): bool => isset($r['et'])))[0]['et']);
    }

    public function testInertWithoutAnEngineConfigured(): void
    {
        $mw = new Middleware(new Camada(env: ['CAMADA_KEY' => ''], transport: $this->a));
        $req = self::request('GET', '/', [], ['REMOTE_ADDR' => FakeAnalyst::BLOCKED_IP]);
        $res = $mw->handle($req, static fn (Request $r): Response => new Response('app'));
        self::assertSame('app', $res->getContent());
        self::assertNull($res->headers->get('x-rid'));
        $mw->terminate($req, $res);
        self::assertSame([], $this->a->events);
    }
}
