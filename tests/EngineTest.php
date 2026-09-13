<?php

declare(strict_types=1);

namespace Camada\Tests;

use Camada\Camada;
use Camada\Context;
use Camada\Guarded;
use Camada\Req;
use Camada\Runtime\Deferred;
use Camada\Version;
use PHPUnit\Framework\TestCase;

/**
 * The engine through the adapter seam: inline enforcement, ordered custom rules, the challenge,
 * the first-party beacon, request capture, app-context events, and the fail-open envelope. The
 * case list mirrors camada-python's test_engine.py (and camada-node's engine, rules and
 * challenge suites) case for case.
 */
final class EngineTest extends TestCase
{
    private const HTML = [['accept', 'text/html,*/*'], ['sec-fetch-dest', 'document']];

    /** @var list<string> */
    private array $dirs = [];
    private FakeAnalyst $a;

    protected function setUp(): void
    {
        Guarded::useStamp(null);
        $this->a = new FakeAnalyst();
    }

    protected function tearDown(): void
    {
        foreach ($this->dirs as $d) {
            foreach (glob($d . '/*') ?: [] as $f) {
                @unlink($f);
            }
            @rmdir($d);
        }
    }

    private function dir(): string
    {
        $d = sys_get_temp_dir() . '/camada-engine-' . getmypid() . '-' . random_int(1, 1_000_000);
        $this->dirs[] = $d;
        return $d;
    }

    /**
     * One engine + one driver per test, loaded unless asked otherwise.
     *
     * @param array<string, mixed> $env
     * @param (\Closure(Context): array{int, list<array{string, string}>, string})|null $handler
     */
    private function host(array $env = [], ?\Closure $handler = null, bool $load = true, mixed ...$opts): Driver
    {
        $engine = Driver::engineWith($this->a, $this->dir(), $env, ...$opts);
        if ($load && $engine->snap !== null) {
            Driver::loaded($engine);
        }
        return new Driver($engine, $handler);
    }

    /** @return list<array<string, mixed>> */
    private function events(Driver $h): array
    {
        $h->engine->spool?->flush();
        return $this->a->allEvents();
    }

    /** @return array<string, mixed> */
    private static function ip(string $addr): array
    {
        return ['headers' => [['x-forwarded-for', $addr]]];
    }

    private function hops1(): void
    {
        $this->a->config['trusted_proxy'] = ['mode' => 'hops', 'hops' => 1];
    }

    // ---- inline blocking ----

    public function testAnswers403BeforeTheAppAndStillShipsTheEvent(): void
    {
        $h = $this->host(['CAMADA_TRUSTED_PROXY' => 'hops:1']);
        $r = $h(new Call('GET', '/admin?x=1', ...self::ip(FakeAnalyst::BLOCKED_IP)));
        self::assertSame(403, $r->status);
        self::assertSame('Forbidden', $r->body);
        self::assertSame('ip4', $r->header('x-block-reason'));
        self::assertSame($this->a->meta()['version'], $r->header('x-block-version'));
        self::assertSame('text/plain', $r->header('content-type'));
        self::assertNull($r->header('x-block-rule'));
        self::assertSame([], $h->seen);
        [$ev] = $this->events($h);
        self::assertSame(403, $ev['st']);
        self::assertSame('ip4', $ev['blk']);
        self::assertSame(FakeAnalyst::BLOCKED_IP, $ev['ip']);
        self::assertSame('/admin', $ev['p']);
        self::assertSame('sdk-php', $ev['tap']);
        self::assertArrayNotHasKey('rl', $ev);
    }

    public function testIgnoresASpoofedXffWithoutTrustedProxyConfig(): void
    {
        $h = $this->host();
        self::assertSame(200, $h(new Call('GET', '/', ...self::ip(FakeAnalyst::BLOCKED_IP)))->status);
        self::assertSame(403, $h(new Call('GET', '/', peer: FakeAnalyst::BLOCKED_IP))->status);
    }

    public function testServerDeliveredTrustedProxyAppliesWhenNoLocalOverride(): void
    {
        $this->hops1();
        $h = $this->host();
        self::assertSame(403, $h(new Call('GET', '/', ...self::ip(FakeAnalyst::BLOCKED_IP)))->status);
    }

    public function testFailsOpenWhileCold(): void
    {
        $this->a->snapshotDown = true;
        $h = $this->host(load: false);
        $prev = ini_set('error_log', $this->dirs[0] . '.log');
        try {
            self::assertSame(200, $h(new Call('GET', '/', peer: FakeAnalyst::BLOCKED_IP))->status);
        } finally {
            ini_set('error_log', $prev === false ? '' : $prev);
        }
        self::assertCount(1, $h->seen);
        self::assertNotNull($h->seen[0]->rid);
        self::assertCount(1, $this->a->snapshotRequests);   // the post-response phase tried (and will retry per cadence)
        $log = (string) file_get_contents($this->dirs[0] . '.log');
        @unlink($this->dirs[0] . '.log');
        self::assertStringContainsString('snapshot poll got status 0', $log);   // cold and unanswered is never silent
    }

    public function testTheSecondRequestReadsTheSnapshotTheFirstOneFetched(): void
    {
        // the request+post-response cycle twice: request 1 is cold and arms the refresh, request 2 enforces from the cache
        $h = $this->host(load: false);
        self::assertSame(200, $h(new Call('GET', '/', peer: FakeAnalyst::BLOCKED_IP))->status);
        self::assertCount(1, $this->a->snapshotRequests);
        self::assertSame(403, $h(new Call('GET', '/', peer: FakeAnalyst::BLOCKED_IP))->status);
        self::assertCount(1, $this->a->snapshotRequests);   // fresh: no second poll
        self::assertFileExists($h->engine->snap?->cacheDir() . '/snapshot.bin');
    }

    public function testHonoursTheAllowSideOverAWiderBlock(): void
    {
        $this->a->container = 'v4';
        $h = $this->host();
        self::assertSame(403, $h(new Call('GET', '/', peer: '10.0.0.9'))->status);
        self::assertSame(200, $h(new Call('GET', '/', peer: FakeAnalyst::ALLOWED_IP))->status);
    }

    // ---- SDK identity ----

    public function testSendsXCamadaSdkOnPollsAndBatches(): void
    {
        $h = $this->host();
        $h(new Call('GET', '/'));
        $this->events($h);
        self::assertSame([Version::SDK_ID], array_values(array_unique($this->a->sdkHeaders)));
        self::assertGreaterThanOrEqual(2, count($this->a->sdkHeaders));
    }

    public function testAsksForV5ByDefaultAndOptsOutAt3(): void
    {
        $this->host();
        $this->host(snapshotVersion: 3);
        self::assertSame(['5', ''], $this->a->snapshotVersions);
    }

    // ---- capture ----

    public function testCapturesOnFinishWithStatusLatencySessionAndRid(): void
    {
        $h = $this->host(handler: static fn (Context $c): array => [201, [['x-app', '1']], 'made']);
        $r = $h(new Call('POST', '/things?q=1&token=secret', headers: [['user-agent', 'UA/1'], ['accept', '*/*']], body: '{}'));
        self::assertSame(201, $r->status);
        self::assertSame('made', $r->body);
        self::assertSame('1', $r->header('x-app'));
        $rid = $r->header('x-rid');
        self::assertNotNull($rid);
        self::assertSame(36, strlen($rid));
        $cookie = $r->header('set-cookie');
        self::assertNotNull($cookie);
        self::assertStringStartsWith('_sfp=', $cookie);
        self::assertStringContainsString('HttpOnly', $cookie);
        self::assertStringContainsString('SameSite=Lax', $cookie);
        self::assertStringNotContainsString('Secure', $cookie);
        [$ev] = $this->events($h);
        self::assertSame($rid, $ev['rid']);
        self::assertSame(explode(';', substr($cookie, 5))[0], $ev['sid']);
        self::assertSame(1, $ev['ns']);
        self::assertSame(201, $ev['st']);
        self::assertIsInt($ev['dur']);
        self::assertGreaterThanOrEqual(0, $ev['dur']);
        self::assertSame('POST', $ev['m']);
        self::assertSame('/things', $ev['p']);
        self::assertSame('?q=1&token=~r', $ev['q']);
        self::assertSame('UA/1', $ev['ua']);
        self::assertSame('172.16.0.9', $ev['ip']);
        self::assertSame('HTTP/1.1', $ev['proto']);
        self::assertSame('x.test', $ev['h']);
        self::assertArrayNotHasKey('blk', $ev);
        self::assertArrayNotHasKey('wrn', $ev);
    }

    public function testReusesTheSessionCookieAndMarksHttpsSecure(): void
    {
        $h = $this->host();
        $r = $h(new Call('GET', '/', headers: [['cookie', 'a=1; _sfp=sess-1; b=2']], https: true));
        self::assertNull($r->header('set-cookie'));
        $r2 = $h(new Call('GET', '/', https: true));
        self::assertStringContainsString('; Secure', (string) $r2->header('set-cookie'));
        $r3 = $h(new Call('GET', '/', headers: [['x-forwarded-proto', 'https']]));
        self::assertStringContainsString('; Secure', (string) $r3->header('set-cookie'));
        $ev = $this->events($h)[0];
        self::assertSame('sess-1', $ev['sid']);
        self::assertSame(0, $ev['ns']);
    }

    public function testKeepsTheAppsOwnCookies(): void
    {
        $h = $this->host(handler: static fn (Context $c): array => [200, [['set-cookie', 'app=1; Path=/'], ['set-cookie', 'b=2']], '']);
        $cookies = $h(new Call('GET', '/'))->headersNamed('set-cookie');
        self::assertCount(3, $cookies);
        self::assertContains('app=1; Path=/', $cookies);
        self::assertContains('b=2', $cookies);
        self::assertNotEmpty(array_filter($cookies, static fn (string $c): bool => str_starts_with($c, '_sfp=')));
    }

    public function testHonoursExcludeAndSampleAndNeverCapturesCredentials(): void
    {
        $this->a->config['exclude'] = ['/health'];
        $h = $this->host();
        $h(new Call('GET', '/health/live'));
        $h(new Call('GET', '/api', headers: [['authorization', 'Bearer very-secret'], ['cookie', 's=1; t=2']]));
        [$ev] = $this->events($h);
        self::assertSame('/api', $ev['p']);
        self::assertSame('Bearer', $ev['auth']);
        self::assertSame(2, $ev['ck']);
        self::assertStringNotContainsString('very-secret', (string) json_encode($ev));
        self::assertStringNotContainsString('s=1', (string) json_encode($ev));
        $this->a->config['sample'] = 0;
        $h->engine->snap?->refresh();
        $h(new Call('GET', '/api'));
        self::assertCount(1, $this->events($h));
    }

    public function testExposesRidSidIpToTheApp(): void
    {
        $h = $this->host();
        $r = $h(new Call('GET', '/'));
        $ctx = $h->seen[0];
        self::assertSame($r->header('x-rid'), $ctx->rid);
        self::assertSame('172.16.0.9', $ctx->ip);
        self::assertNotNull($ctx->sid);
        self::assertSame($h->engine, $ctx->engine);
    }

    public function testAnAppExceptionShipsSt500AndPropagates(): void
    {
        $h = $this->host(handler: static function (Context $c): array {
            throw new \RuntimeException('app bug');
        });
        try {
            $h(new Call('GET', '/crash'));
            self::fail('the app exception must propagate');
        } catch (\RuntimeException $e) {
            self::assertSame('app bug', $e->getMessage());
        }
        [$ev] = $this->events($h);
        self::assertSame('/crash', $ev['p']);
        self::assertSame(500, $ev['st']);
    }

    public function testTheRouteRidesTheEventWhenTheHostKnowsIt(): void
    {
        $h = $this->host(handler: static function (Context $c): array {
            if ($c->req !== null) {
                $c->req->route = '/things/{id}';
            }
            return [200, [], 'ok'];
        });
        $h(new Call('GET', '/things/7'));
        self::assertSame('/things/{id}', $this->events($h)[0]['rt']);
    }

    // ---- track ----

    public function testTrackShipsAnAppContextEventWithAHashedUid(): void
    {
        $h = $this->host(handler: function (Context $c): array {
            $c->engine?->track($c, 'login_failed', 'alice@example.com');
            return [401, [], ''];
        });
        $r = $h(new Call('POST', '/login', body: 'x=1'));
        $evs = $this->events($h);
        $tracked = array_values(array_filter($evs, static fn (array $e): bool => isset($e['et'])))[0];
        self::assertSame('login_failed', $tracked['et']);
        self::assertSame('sdk-php', $tracked['tap']);
        self::assertSame($r->header('x-rid'), $tracked['rid']);
        self::assertSame(substr(hash_hmac('sha256', 'uid:alice@example.com', 'tok-test'), 0, 32), $tracked['uid']);
        self::assertStringNotContainsString('alice', (string) json_encode($evs));
        self::assertSame('172.16.0.9', $tracked['ip']);
        self::assertArrayNotHasKey('p', $tracked);
    }

    public function testTrackWithoutAUserAndWithoutContext(): void
    {
        $h = $this->host();
        $h->engine->track(null, 'signup');
        [$ev] = $this->events($h);
        self::assertSame('signup', $ev['et']);
        self::assertNull($ev['uid']);
        self::assertNull($ev['rid']);
    }

    // ---- beacon ----

    public function testServesTheScriptAndBatchesFpAsASigRowWithTheResolvedIp(): void
    {
        $this->hops1();
        $h = $this->host();
        $js = $h(new Call('GET', '/_cam/b.js'));
        self::assertSame(200, $js->status);
        self::assertSame('application/javascript', $js->header('content-type'));
        self::assertStringContainsString('@camada/browser', $js->body);
        self::assertSame('public, max-age=3600', $js->header('cache-control'));
        $body = (string) json_encode(['sdk' => '@camada/browser/0.2.0', 'rid' => 'r-1', 'ip' => '9.9.9.9', 'tap' => 'proxy', 'scr' => '1x1']);
        $fp = $h(new Call('POST', '/_cam/fp', headers: [['x-forwarded-for', '198.18.0.5'], ['content-type', 'application/json']], body: $body));
        self::assertSame(204, $fp->status);
        self::assertSame('no-store', $fp->header('cache-control'));
        self::assertSame([], $h->seen);
        [$row] = $this->events($h);
        self::assertSame(1, $row['sig']);
        self::assertSame('198.18.0.5', $row['ip']);
        self::assertSame('sdk-php', $row['tap']);
        self::assertSame('1x1', $row['scr']);
        self::assertSame('r-1', $row['rid']);
    }

    public function testDropsJunkBodiesInsteadOfShippingThem(): void
    {
        $h = $this->host();
        foreach (['not json', '[1,2]', '42', ''] as $junk) {
            self::assertSame(204, $h(new Call('POST', '/_cam/fp', body: $junk))->status);
        }
        self::assertSame([], $this->events($h));
    }

    public function testRejectsOversizedPostsDeclaredOrActual(): void
    {
        $h = $this->host();
        self::assertSame(413, $h(new Call('POST', '/_cam/fp', body: '{}', contentLength: 40000))->status);
        self::assertSame(413, $h(new Call('POST', '/_cam/fp', body: '{' . str_repeat(' ', 33000) . '}'))->status);
        self::assertSame([], $this->events($h));
    }

    public function testFallsThroughToTheAppWhenTheTenantDisabledTheBeacon(): void
    {
        $this->a->config['beacon'] = false;
        $h = $this->host();
        self::assertSame('hello', $h(new Call('GET', '/_cam/b.js'))->body);
        self::assertSame('hello', $h(new Call('POST', '/_cam/fp', body: '{}'))->body);
        self::assertSame('', $h->engine->scriptTag($h->seen[0]));
    }

    public function testScriptTagCarriesTheRid(): void
    {
        $h = $this->host();
        $r = $h(new Call('GET', '/'));
        self::assertSame('<script src="/_cam/b.js?r=' . $r->header('x-rid') . '" async></script>', $h->engine->scriptTag($h->seen[0]));
        self::assertSame('<script src="/_cam/b.js" async></script>', $h->engine->scriptTag(null));
    }

    public function testEnforcementComesBeforeTheBeaconEndpoints(): void
    {
        $h = $this->host();
        self::assertSame(403, $h(new Call('GET', '/_cam/b.js', peer: FakeAnalyst::BLOCKED_IP))->status);
    }

    public function testBeaconPathsCanMove(): void
    {
        $h = $this->host(scriptPath: '/static/c.js', fpPath: '/static/fp');
        self::assertSame(200, $h(new Call('GET', '/static/c.js'))->status);
        self::assertSame('hello', $h(new Call('GET', '/_cam/b.js'))->body);
        self::assertSame('<script src="/static/c.js" async></script>', $h->engine->scriptTag(null));
        self::assertSame(204, $h(new Call('POST', '/static/fp', body: '{}'))->status);
    }

    // ---- rules (v5) ----

    private function v5(): void
    {
        $this->a->container = 'v5';
        $this->hops1();
    }

    public function testSkipRuleBeatsTheWiderBlock(): void
    {
        $this->v5();
        $h = $this->host();
        self::assertSame(200, $h(new Call('GET', FakeAnalyst::SKIP_PATH, ...self::ip(FakeAnalyst::BLOCKED_IP)))->status);
        [$ev] = $this->events($h);
        self::assertArrayNotHasKey('blk', $ev);
        self::assertArrayNotHasKey('wrn', $ev);
    }

    public function testBlocksByRuleWithXBlockRuleAndShipsRl(): void
    {
        $this->v5();
        $h = $this->host();
        $r = $h(new Call('GET', '/', ...self::ip(FakeAnalyst::RULE_BLOCKED_IP)));
        self::assertSame(403, $r->status);
        self::assertSame('rule', $r->header('x-block-reason'));
        self::assertSame('builtin:block', $r->header('x-block-rule'));
        [$ev] = $this->events($h);
        self::assertSame('rule', $ev['blk']);
        self::assertSame('builtin:block', $ev['rl']);
    }

    public function testBlocksByPathUaAndHeaderRules(): void
    {
        $this->v5();
        $h = $this->host();
        self::assertSame('cr_00000000000c', $h(new Call('GET', FakeAnalyst::RULE_BLOCKED_PATH))->header('x-block-rule'));
        self::assertSame(403, $h(new Call('GET', '/', headers: [['user-agent', FakeAnalyst::BLOCKED_UA]]))->status);
        self::assertSame(403, $h(new Call('GET', '/', headers: [[strtoupper(FakeAnalyst::BLOCKED_HEADER), FakeAnalyst::BLOCKED_HEADER_VALUE]]))->status);   // any spelling
        self::assertSame(200, $h(new Call('GET', '/', headers: [[FakeAnalyst::BLOCKED_HEADER, 'other']]))->status);
        self::assertSame(200, $h(new Call('GET', '/'))->status);
    }

    public function testWarnPassesAndStampsWrn(): void
    {
        $this->v5();
        $h = $this->host();
        self::assertSame(200, $h(new Call('GET', '/', headers: [['user-agent', FakeAnalyst::WARN_UA]]))->status);
        [$ev] = $this->events($h);
        self::assertSame('cr_00000000000e', $ev['wrn']);
        self::assertSame(200, $ev['st']);
    }

    public function testStillEnforcesAgainstAnAnalystThatOnlyPublishesV3(): void
    {
        $this->v5();
        $this->a->container = 'v3';
        $h = $this->host();
        self::assertSame(403, $h(new Call('GET', '/', ...self::ip(FakeAnalyst::BLOCKED_IP)))->status);
        self::assertSame(200, $h(new Call('GET', '/', headers: [['user-agent', FakeAnalyst::BLOCKED_UA]]))->status);   // a rule-only signal: v3 carries no rules
    }

    // ---- challenge ----

    private static function nonceOf(string $page): string
    {
        return explode('"', explode('name="nonce" value="', $page)[1])[0];
    }

    public function testServesThePageForAnHtmlNavigationAndShipsBlkChallenge(): void
    {
        $this->a->container = 'v4';
        $h = $this->host();
        $r = $h(new Call('GET', '/account?tab=1', headers: self::HTML, peer: FakeAnalyst::CHALLENGED_IP));
        self::assertSame(403, $r->status);
        self::assertSame('text/html; charset=utf-8', $r->header('content-type'));
        self::assertSame('1', $r->header('x-camada-challenge'));
        self::assertSame('no-store', $r->header('cache-control'));
        self::assertStringContainsString('action="/__camada/challenge"', $r->body);
        self::assertStringContainsString('name="to" value="/account?tab=1"', $r->body);
        self::assertSame([], $h->seen);
        [$ev] = $this->events($h);
        self::assertSame(403, $ev['st']);
        self::assertSame('challenge', $ev['blk']);
        self::assertSame('/account', $ev['p']);
    }

    public function testAnswersJsonForANonHtmlRequest(): void
    {
        $this->a->container = 'v4';
        $h = $this->host();
        $r = $h(new Call('GET', '/api', headers: [['accept', 'application/json']], peer: FakeAnalyst::CHALLENGED_IP));
        self::assertSame(403, $r->status);
        self::assertSame('application/json', $r->header('content-type'));
        self::assertSame(['error' => 'challenge_required'], json_decode($r->body, true));
        $r2 = $h(new Call('GET', '/api', headers: [['accept', 'text/html'], ['sec-fetch-dest', 'empty']], peer: FakeAnalyst::CHALLENGED_IP));
        self::assertSame('application/json', $r2->header('content-type'));
    }

    public function testBlocksOutrightRatherThanChallengingABlockedIp(): void
    {
        $this->a->container = 'v4';
        $h = $this->host();
        $r = $h(new Call('GET', '/', headers: self::HTML, peer: FakeAnalyst::BLOCKED_IP));
        self::assertSame(403, $r->status);
        self::assertNull($r->header('x-camada-challenge'));
    }

    public function testVerifySetsCchRedirectsBackAndShipsCh1(): void
    {
        $this->a->container = 'v4';
        $h = $this->host();
        $page = $h(new Call('GET', '/back?x=1', headers: self::HTML, peer: FakeAnalyst::CHALLENGED_IP))->body;
        $nonce = self::nonceOf($page);
        $form = "nonce={$nonce}&solution=" . ChallengeTest::solve($nonce) . '&to=%2Fback%3Fx%3D1';
        $r = $h(new Call('POST', '/__camada/challenge', headers: [['content-type', 'application/x-www-form-urlencoded']], body: $form, peer: FakeAnalyst::CHALLENGED_IP));
        self::assertSame(302, $r->status);
        self::assertSame('/back?x=1', $r->header('location'));
        self::assertSame('no-store', $r->header('cache-control'));
        $cookie = (string) $r->header('set-cookie');
        self::assertStringStartsWith('_cch=', $cookie);
        self::assertStringContainsString('HttpOnly', $cookie);
        $evs = $this->events($h);
        $last = $evs[count($evs) - 1];
        self::assertSame(200, $last['st']);
        self::assertSame(1, $last['ch']);
        self::assertSame('/__camada/challenge', $last['p']);
        // the holder of a valid _cch passes; a cookie minted for another ip does not
        $bare = explode(';', $cookie)[0];
        self::assertSame(200, $h(new Call('GET', '/back', headers: [...self::HTML, ['cookie', $bare]], peer: FakeAnalyst::CHALLENGED_IP))->status);
        self::assertSame(200, $h(new Call('GET', '/back', headers: [...self::HTML, ['cookie', $bare]], peer: '192.0.2.21'))->status);   // not challenged at all
        $forged = '_cch=' . preg_replace('/0/', '1', substr($bare, 5), 1);
        self::assertSame(403, $h(new Call('GET', '/back', headers: [...self::HTML, ['cookie', $forged]], peer: FakeAnalyst::CHALLENGED_IP))->status);
    }

    public function testWrongSolutionOrForgedNonceReservesThePage(): void
    {
        $this->a->container = 'v4';
        $h = $this->host();
        $nonce = self::nonceOf($h(new Call('GET', '/', headers: self::HTML, peer: FakeAnalyst::CHALLENGED_IP))->body);
        $r = $h(new Call('POST', '/__camada/challenge', body: "nonce={$nonce}&solution=1&to=%2F", peer: FakeAnalyst::CHALLENGED_IP));
        self::assertSame(403, $r->status);
        self::assertNull($r->header('set-cookie'));
        self::assertStringContainsString('camada-f', $r->body);
        $forged = str_repeat('f', 32);
        $r = $h(new Call('POST', '/__camada/challenge', body: "nonce={$forged}&solution=" . ChallengeTest::solve($forged) . '&to=%2F', peer: FakeAnalyst::CHALLENGED_IP));
        self::assertSame(403, $r->status);
        self::assertNull($r->header('set-cookie'));
    }

    public function testNeverRedirectsOffSite(): void
    {
        $this->a->container = 'v4';
        $h = $this->host();
        $nonce = $h->engine->kit?->nonce(FakeAnalyst::CHALLENGED_IP, Camada::nowMs()) ?? '';
        $r = $h(new Call('POST', '/__camada/challenge', body: "nonce={$nonce}&solution=" . ChallengeTest::solve($nonce) . '&to=https%3A%2F%2Fevil', peer: FakeAnalyst::CHALLENGED_IP));
        self::assertSame(302, $r->status);
        self::assertSame('/', $r->header('location'));
    }

    public function testRefusesAnOversizedVerifyBody(): void
    {
        $this->a->container = 'v4';
        $h = $this->host();
        self::assertSame(413, $h(new Call('POST', '/__camada/challenge', body: 'a=' . str_repeat('b', 5000), peer: FakeAnalyst::CHALLENGED_IP))->status);
    }

    public function testNoIpMeansNoChallenge(): void
    {
        $this->a->container = 'v4';
        $h = $this->host();
        self::assertSame(200, $h(new Call('GET', '/', headers: self::HTML, peer: null))->status);
    }

    public function testSwitchedOffByEnvOrOption(): void
    {
        $this->a->container = 'v4';
        self::assertSame(200, $this->host(['CAMADA_CHALLENGE' => '0'])(new Call('GET', '/', headers: self::HTML, peer: FakeAnalyst::CHALLENGED_IP))->status);
        self::assertSame(200, $this->host(challenge: false)(new Call('GET', '/', headers: self::HTML, peer: FakeAnalyst::CHALLENGED_IP))->status);
    }

    public function testServeChallengeOnDemand(): void
    {
        $this->a->container = 'v4';
        $h = $this->host(handler: static function (Context $c): array {
            $answer = $c->engine?->serveChallenge($c);
            if ($answer !== null) {
                return [$answer->status, $answer->headers, $answer->body];
            }
            return [200, [], 'secret page'];
        });
        $r = $h(new Call('GET', '/challenge-me', headers: self::HTML));
        self::assertSame(403, $r->status);
        self::assertStringContainsString('camada-f', $r->body);
        $evs = $this->events($h);
        self::assertCount(1, $evs);   // one request, one event
        self::assertSame('challenge', $evs[0]['blk']);
        $nonce = self::nonceOf($r->body);
        $ok = $h(new Call('POST', '/__camada/challenge', body: "nonce={$nonce}&solution=" . ChallengeTest::solve($nonce) . '&to=%2Fchallenge-me'));
        $cookie = explode(';', (string) $ok->header('set-cookie'))[0];
        self::assertSame('secret page', $h(new Call('GET', '/challenge-me', headers: [...self::HTML, ['cookie', $cookie]]))->body);
    }

    // ---- fail open ----

    public function testKeepsServingWhenIngestIsDown(): void
    {
        $this->a->ingestDown = true;
        $h = $this->host();
        self::assertSame(200, $h(new Call('GET', '/'))->status);
        $prev = ini_set('error_log', $this->dirs[0] . '.log');
        try {
            self::assertSame([], $this->events($h));
        } finally {
            ini_set('error_log', $prev === false ? '' : $prev);
            @unlink($this->dirs[0] . '.log');
        }
        self::assertSame(1, $h->engine->spool?->dropped());
    }

    public function testDisabledBypassesTheSdkEntirely(): void
    {
        $h = $this->host(['CAMADA_DISABLED' => '1'], load: false);
        self::assertNull($h->engine->snap);
        self::assertTrue($h->engine->disabled());
        $r = $h(new Call('GET', '/', peer: FakeAnalyst::BLOCKED_IP));
        self::assertSame(200, $r->status);
        self::assertNull($r->header('x-rid'));
        self::assertSame([], $this->a->snapshotRequests);
        self::assertNull($h->engine->wantsBody('POST', '/_cam/fp'));
    }

    public function testStaysInertWithoutCredentials(): void
    {
        $h = $this->host(['CAMADA_KEY' => ''], load: false);
        self::assertNull($h->engine->env);
        self::assertSame(200, $h(new Call('GET', '/', peer: FakeAnalyst::BLOCKED_IP))->status);
        self::assertSame('', $h->engine->scriptTag(null));
        self::assertNull($h->engine->serveChallenge(null));
        $h->engine->track(null, 'x');
        self::assertSame([], $this->a->events);
    }

    public function testACamadaBugCostsTheJoinNotTheRequest(): void
    {
        $engine = new class (env: array_merge(Driver::ENV, ['CAMADA_CACHE_DIR' => $this->dir()]), transport: $this->a) extends Camada {
            protected function decide(Req $req, ?string $body): never
            {
                throw new \RuntimeException('sdk bug');
            }
        };
        Driver::loaded($engine);
        $h = new Driver($engine);
        $prev = ini_set('error_log', $this->dirs[0] . '.log');
        try {
            $r = $h(new Call('GET', '/', peer: FakeAnalyst::BLOCKED_IP));
        } finally {
            ini_set('error_log', $prev === false ? '' : $prev);
        }
        self::assertSame(200, $r->status);
        self::assertSame('hello', $r->body);
        self::assertStringContainsString('sdk bug', (string) file_get_contents($this->dirs[0] . '.log'));
        @unlink($this->dirs[0] . '.log');
    }

    public function testTheDefaultEngineIsALazySingletonFromTheEnvironment(): void
    {
        Camada::setDefault(null);
        putenv('CAMADA_DISABLED=1');
        putenv('CAMADA_KEY=a.b');
        try {
            $d = Camada::default();
            self::assertSame($d, Camada::default());
            self::assertTrue($d->disabled());
            self::assertNotNull($d->env);
        } finally {
            putenv('CAMADA_DISABLED');
            putenv('CAMADA_KEY');
            Camada::setDefault(null);
        }
    }

    public function testTheDeferredPhaseIsArmedOnceAndTheRefreshOnlyWhenStale(): void
    {
        $h = $this->host();
        $d = $h->engine->deferred();
        $h->engine->handle(new Req('GET', '/', peer: '172.16.0.9'));
        self::assertTrue($d->armed(Deferred::SHIP));
        self::assertFalse($d->armed(Deferred::REFRESH));   // just loaded: fresh
        $d->runTasks();
        $h->engine->snap?->refresh();
        self::assertCount(2, $this->a->snapshotRequests);
    }
}
