<?php

declare(strict_types=1);

namespace Camada\Tests;

use Camada\Runtime\Cache;
use Camada\Snapshot\Client;
use PHPUnit\Framework\TestCase;

/**
 * What only a real SAPI can show: Sapi::run() over php -S with nothing but $_SERVER,
 * php://input and header() — the response stamps, the body cap, the answers camada sends
 * itself, an app that throws, the kill switch, and the post-response phase running after the
 * client has its bytes. The cache is seeded by a Client in this process (what a previous
 * request's refresh leaves behind), so the server enforces without ever reaching an analyst.
 */
final class SapiTest extends TestCase
{
    private const HTML = ['accept' => 'text/html,*/*', 'sec-fetch-dest' => 'document'];
    private string $dir;
    private ?PhpServer $app = null;
    private ?PhpServer $analyst = null;

    protected function setUp(): void
    {
        $this->dir = sys_get_temp_dir() . '/camada-sapi-' . getmypid() . '-' . random_int(1, 1_000_000);
    }

    protected function tearDown(): void
    {
        $this->app?->stop();
        $this->analyst?->stop();
        foreach (glob($this->dir . '/*') ?: [] as $f) {
            @unlink($f);
        }
        @rmdir($this->dir);
    }

    /** @param array<string, string> $env */
    private function boot(array $env = [], string $container = 'v4', bool $seed = true, int $workers = 1): PhpServer
    {
        $this->analyst ??= new PhpServer(__DIR__ . '/fixtures/analyst-server.php', ['ANALYST_SINK' => $this->dir . '/sink.ndjson', 'ANALYST_DELAY_MS' => $env['ANALYST_DELAY_MS'] ?? '0']);
        if ($seed) {
            $a = new FakeAnalyst();
            $a->container = $container;
            (new Client($this->analyst->url . '/snapshot', 'snap-test', new Cache($this->dir), $a))->refresh();
        }
        $this->app = new PhpServer(__DIR__ . '/fixtures/sapi-app.php', array_merge([
            'CAMADA_KEY' => 'tok-test.snap-test',
            'CAMADA_INGEST_URL' => $this->analyst->url,
            'CAMADA_SNAPSHOT_URL' => $this->analyst->url . '/snapshot',
            'CAMADA_TRUSTED_PROXY' => 'hops:1',
            'CAMADA_CACHE_DIR' => $this->dir,
        ], $env), workers: $workers);
        return $this->app;
    }

    /** @return list<array<string, mixed>> */
    private function spool(int $expect): array
    {
        $deadline = microtime(true) + 5;
        do {
            $rows = [];
            foreach (@file($this->dir . '/events.ndjson', FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES) ?: [] as $line) {   // absent until the first event lands
                $row = json_decode($line, true);
                if (is_array($row)) {
                    $rows[] = $row;
                }
            }
            if (count($rows) >= $expect) {
                return $rows;
            }
            usleep(20_000);
        } while (microtime(true) < $deadline);
        self::fail("expected {$expect} spooled rows, found " . count($rows));
    }

    public function testBlocksBeforeTheAppWithTheContractHeaders(): void
    {
        $app = $this->boot();
        $r = $app->request('GET', '/anything?x=1', ['x-forwarded-for' => FakeAnalyst::BLOCKED_IP]);
        self::assertSame(403, $r['status']);
        self::assertSame('Forbidden', $r['body']);
        self::assertSame(['ip4'], $r['headers']['x-block-reason']);
        self::assertSame(['text/plain'], $r['headers']['content-type']);
        self::assertSame(['9'], $r['headers']['content-length']);
        self::assertArrayNotHasKey('x-rid', $r['headers']);
        [$ev] = $this->spool(1);
        self::assertSame(403, $ev['st']);
        self::assertSame('ip4', $ev['blk']);
        self::assertSame(FakeAnalyst::BLOCKED_IP, $ev['ip']);
        self::assertSame('/anything', $ev['p']);
        self::assertSame('?x=1', $ev['q']);
    }

    public function testStampsTheResponseAndShipsTheEventAfterIt(): void
    {
        $app = $this->boot();
        $r = $app->request('GET', '/', ['user-agent' => 'UA/1', 'accept' => 'text/plain']);
        self::assertSame(200, $r['status']);
        $rid = $r['headers']['x-rid'][0] ?? '';
        self::assertMatchesRegularExpression('/^[0-9a-f-]{36}$/', $rid);
        self::assertSame("hello {$rid}", $r['body']);
        self::assertSame([(string) strlen($r['body'])], $r['headers']['content-length']);   // the fallback finisher sets it so the client can stop reading
        $cookie = $r['headers']['set-cookie'][0] ?? '';
        self::assertStringStartsWith('_sfp=', $cookie);
        self::assertStringContainsString('HttpOnly; SameSite=Lax', $cookie);
        [$ev] = $this->spool(1);
        self::assertSame($rid, $ev['rid']);
        self::assertSame(200, $ev['st']);
        self::assertIsInt($ev['dur']);
        self::assertSame('UA/1', $ev['ua']);
        self::assertSame('text/plain', $ev['acc']);
        self::assertSame('127.0.0.1', $ev['ip']);
        self::assertSame('GET', $ev['m']);
        self::assertSame('HTTP/1.1', $ev['proto']);
        self::assertSame(1, $ev['ns']);
        self::assertStringContainsString('user-agent', (string) $ev['hord']);
        $r2 = $app->request('GET', '/status', ['cookie' => explode(';', $cookie)[0]]);
        self::assertSame(201, $r2['status']);
        self::assertSame(['1'], $r2['headers']['x-app']);
        self::assertArrayNotHasKey('set-cookie', $r2['headers']);
        $ev2 = $this->spool(2)[1];
        self::assertSame(201, $ev2['st']);
        self::assertSame(0, $ev2['ns']);
        self::assertSame($ev['sid'], $ev2['sid']);
    }

    public function testTheScriptTagAndTheBeaconEndpoints(): void
    {
        $app = $this->boot();
        $tag = $app->request('GET', '/tag');
        self::assertSame('<script src="/_cam/b.js?r=' . $tag['headers']['x-rid'][0] . '" async></script>', $tag['body']);
        $js = $app->request('GET', '/_cam/b.js');
        self::assertSame(200, $js['status']);
        self::assertSame(['application/javascript'], $js['headers']['content-type']);
        self::assertSame(['public, max-age=3600'], $js['headers']['cache-control']);
        self::assertStringContainsString('@camada/browser', $js['body']);
        $fp = $app->request('POST', '/_cam/fp', ['content-type' => 'application/json', 'x-forwarded-for' => '198.18.0.5'], '{"rid":"r-1","tz":"UTC"}');
        self::assertSame(204, $fp['status']);
        self::assertSame(['no-store'], $fp['headers']['cache-control']);
        $big = $app->request('POST', '/_cam/fp', ['content-type' => 'application/json'], '{"pad":"' . str_repeat('x', 40000) . '"}');
        self::assertSame(413, $big['status']);
        $rows = $this->spool(2);
        $sig = array_values(array_filter($rows, static fn (array $r): bool => isset($r['sig'])))[0];
        self::assertSame('198.18.0.5', $sig['ip']);
        self::assertSame('sdk-php', $sig['tap']);
        self::assertSame('UTC', $sig['tz']);
    }

    public function testTheChallengeRoundTripOverHttp(): void
    {
        $app = $this->boot();
        $page = $app->request('GET', '/account?tab=1', self::HTML + ['x-forwarded-for' => FakeAnalyst::CHALLENGED_IP]);
        self::assertSame(403, $page['status']);
        self::assertSame(['1'], $page['headers']['x-camada-challenge']);
        self::assertSame(['no-store'], $page['headers']['cache-control']);
        self::assertStringContainsString('name="to" value="/account?tab=1"', $page['body']);
        $json = $app->request('GET', '/api', ['accept' => 'application/json', 'x-forwarded-for' => FakeAnalyst::CHALLENGED_IP]);
        self::assertSame(403, $json['status']);
        self::assertSame('{"error":"challenge_required"}', $json['body']);
        $nonce = explode('"', explode('name="nonce" value="', $page['body'])[1])[0];
        $form = "nonce={$nonce}&solution=" . ChallengeTest::solve($nonce) . '&to=%2Faccount%3Ftab%3D1';
        $ok = $app->request('POST', '/__camada/challenge', ['content-type' => 'application/x-www-form-urlencoded', 'x-forwarded-for' => FakeAnalyst::CHALLENGED_IP], $form);
        self::assertSame(302, $ok['status']);
        self::assertSame(['/account?tab=1'], $ok['headers']['location']);
        $cookie = explode(';', $ok['headers']['set-cookie'][0])[0];
        self::assertStringStartsWith('_cch=', $cookie);
        $back = $app->request('GET', '/account?tab=1', self::HTML + ['x-forwarded-for' => FakeAnalyst::CHALLENGED_IP, 'cookie' => $cookie]);
        self::assertSame(404, $back['status']);   // the app's own 404: camada let it through
        self::assertArrayHasKey('x-rid', $back['headers']);
        $gate = $app->request('GET', '/gate', self::HTML);
        self::assertSame(403, $gate['status']);
        self::assertStringContainsString('camada-f', $gate['body']);
        $nonce2 = explode('"', explode('name="nonce" value="', $gate['body'])[1])[0];
        $ok2 = $app->request('POST', '/__camada/challenge', ['content-type' => 'application/x-www-form-urlencoded'], "nonce={$nonce2}&solution=" . ChallengeTest::solve($nonce2) . '&to=%2Fgate');
        $cookie2 = explode(';', $ok2['headers']['set-cookie'][0])[0];
        self::assertSame('secret page', $app->request('GET', '/gate', self::HTML + ['cookie' => $cookie2])['body']);
        $evs = $this->spool(5);
        $kinds = array_map(static fn (array $e): string => ($e['blk'] ?? '') . '/' . ($e['ch'] ?? '') . '/' . $e['st'], $evs);
        self::assertContains('challenge//403', $kinds);
        self::assertContains('/1/200', $kinds);
    }

    public function testTrackAndTheBodyReachTheApp(): void
    {
        $app = $this->boot();
        $r = $app->request('POST', '/track', ['content-type' => 'application/x-www-form-urlencoded'], 'user=alice');
        self::assertSame(401, $r['status']);
        $echo = $app->request('POST', '/echo', ['content-type' => 'text/plain'], str_repeat('b', 70_000));
        self::assertSame(str_repeat('b', 70_000), $echo['body']);   // camada never reads a body it was not asked for
        $rows = $this->spool(3);
        $tracked = array_values(array_filter($rows, static fn (array $e): bool => isset($e['et'])))[0];
        self::assertSame('login_failed', $tracked['et']);
        self::assertSame(substr(hash_hmac('sha256', 'uid:alice@example.com', 'tok-test'), 0, 32), $tracked['uid']);
        self::assertSame($rows[1]['rid'] ?? $rows[0]['rid'], $tracked['rid']);
        self::assertStringNotContainsString('alice', (string) json_encode($rows));
    }

    public function testAnAppExceptionShipsSt500(): void
    {
        $app = $this->boot();
        $r = $app->request('GET', '/crash');
        self::assertSame(500, $r['status']);
        self::assertArrayHasKey('x-rid', $r['headers']);
        [$ev] = $this->spool(1);
        self::assertSame(500, $ev['st']);
        self::assertSame('/crash', $ev['p']);
        self::assertStringContainsString('app bug', $app->output());   // the app's own error, reported by PHP as usual
    }

    public function testTheKillSwitchBypassesEverything(): void
    {
        $app = $this->boot(['CAMADA_DISABLED' => '1']);
        $r = $app->request('GET', '/', ['x-forwarded-for' => FakeAnalyst::BLOCKED_IP]);
        self::assertSame(200, $r['status']);
        self::assertSame('hello -', $r['body']);
        self::assertArrayNotHasKey('x-rid', $r['headers']);
        self::assertArrayNotHasKey('set-cookie', $r['headers']);
        self::assertSame(404, $app->request('GET', '/_cam/b.js')['status']);
        self::assertSame('', $app->request('GET', '/tag')['body']);
        self::assertFileDoesNotExist($this->dir . '/events.ndjson');
    }

    public function testTheResponseEndsBeforeThePostResponsePhase(): void
    {
        // a stale cache and a slow analyst: the client has its bytes long before the refresh returns,
        // and the next request sees what that refresh wrote (204 -> nothing published -> the blocked IP passes).
        // Two workers: a single-process php -S queues the next request behind the first one's refresh.
        $app = $this->boot(['ANALYST_DELAY_MS' => '1500'], workers: 2);
        $cache = new Cache($this->dir);
        $state = $cache->readJson('state.json') ?? [];
        $state['loaded_at'] = microtime(true) - 3600;
        $cache->writeJson('state.json', $state);
        self::assertSame(403, $app->request('GET', '/', ['x-forwarded-for' => FakeAnalyst::BLOCKED_IP])['status']);   // still enforcing from the stale copy
        $t0 = microtime(true);
        $r = $app->request('GET', '/', ['x-forwarded-for' => FakeAnalyst::BLOCKED_IP]);
        $ms = (microtime(true) - $t0) * 1000;
        self::assertSame(403, $r['status']);
        self::assertLessThan(1000, $ms, 'the response waited on the post-response refresh');
        $deadline = microtime(true) + 6;
        do {
            $after = $app->request('GET', '/', ['x-forwarded-for' => FakeAnalyst::BLOCKED_IP]);   // until the refreshing worker's write lands
        } while ($after['status'] !== 200 && microtime(true) < $deadline);
        self::assertSame(200, $after['status']);
        self::assertTrue(($cache->readJson('state.json') ?? [])['none'] ?? false);
        self::assertStringNotContainsString('PHP Warning', $app->output());
    }

    public function testADueSpoolShipsInThePostResponsePhase(): void
    {
        $app = $this->boot();
        $app->request('GET', '/');
        $this->spool(1);
        $cache = new Cache($this->dir);
        $cache->writeJson('flush.json', ['last_flush' => microtime(true) - 20, 'dropped' => 0]);   // the 15 s clock has run out
        $app->request('GET', '/status');
        $deadline = microtime(true) + 5;
        while (!file_exists($this->dir . '/sink.ndjson') && microtime(true) < $deadline) {
            usleep(20_000);
        }
        $batches = array_map(static fn (string $l): mixed => json_decode($l, true), file($this->dir . '/sink.ndjson', FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES) ?: []);
        self::assertCount(1, $batches);
        self::assertIsArray($batches[0]);
        self::assertCount(2, $batches[0]);
        self::assertSame([200, 201], array_column($batches[0], 'st'));
        self::assertFileDoesNotExist($this->dir . '/events.ndjson');
        self::assertSame([], glob($this->dir . '/events.*.sending') ?: []);
    }

    public function testADeadAnalystCostsNothingButOneLogLine(): void
    {
        $dead = PhpServer::freePort();
        $app = $this->boot(['CAMADA_INGEST_URL' => "http://127.0.0.1:{$dead}", 'CAMADA_SNAPSHOT_URL' => "http://127.0.0.1:{$dead}/snapshot"], seed: false);
        self::assertSame(200, $app->request('GET', '/', ['x-forwarded-for' => FakeAnalyst::BLOCKED_IP])['status']);   // cold: fail open
        $cache = new Cache($this->dir);
        $cache->writeJson('flush.json', ['last_flush' => 0, 'dropped' => 0]);
        self::assertSame(200, $app->request('GET', '/api')['status']);   // ships (and drops) the spool post-response
        usleep(300_000);
        self::assertSame(200, $app->request('GET', '/api')['status']);
        $out = $app->output();
        self::assertStringNotContainsString('PHP Warning', $out);
        self::assertStringNotContainsString('PHP Fatal', $out);
        self::assertSame(1, substr_count($out, '[camada] suppressed error'), $out);
    }
}
