<?php

declare(strict_types=1);

namespace Camada\Tests;

use Camada\Config;
use Camada\Env;
use PHPUnit\Framework\TestCase;

final class ConfigTest extends TestCase
{
    public function testKeySplitsOnTheFirstDot(): void
    {
        self::assertSame(['tok-acme', 'snap-acme'], Config::parseKey('tok-acme.snap-acme'));
        self::assertSame(['a', 'b.c'], Config::parseKey('a.b.c'));
    }

    public function testKeyRejectsMissingHalves(): void
    {
        foreach ([null, '', 'nodot', '.snap', 'tok.'] as $bad) {
            self::assertNull(Config::parseKey($bad), (string) $bad);
        }
    }

    public function testRemoteConfigIgnoresAnythingButAnObject(): void
    {
        self::assertSame(['beacon' => false], Config::remoteConfig(['beacon' => false]));
        self::assertNull(Config::remoteConfig([1, 2]));
        self::assertNull(Config::remoteConfig('x'));
        self::assertNull(Config::remoteConfig(null));
    }

    public function testEnvResolvesTheKeyAndTheDefaults(): void
    {
        $e = Env::resolve(['CAMADA_KEY' => 'tok.snap']);
        self::assertNotNull($e);
        self::assertSame('tok', $e->ingestToken);
        self::assertSame('snap', $e->snapToken);
        self::assertSame('tok.snap', $e->secret);
        self::assertSame(Env::DEFAULT_INGEST_URL, $e->ingestUrl);
        self::assertSame(Env::DEFAULT_INGEST_URL . '/snapshot', $e->snapshotUrl);
        self::assertFalse($e->serverless);
        self::assertNull($e->trustedProxy);
    }

    public function testEnvAcceptsTheSplitTokensAndTheOverrides(): void
    {
        $e = Env::resolve([
            'CAMADA_TOKEN' => 'tok', 'CAMADA_SNAPSHOT_TOKEN' => 'snap', 'CAMADA_INGEST_URL' => 'http://localhost:8787/',
            'CAMADA_SNAPSHOT_URL' => 'http://other/snap', 'CAMADA_SERVERLESS' => '1', 'CAMADA_TRUSTED_PROXY' => 'hops:1',
        ]);
        self::assertNotNull($e);
        self::assertSame('http://localhost:8787', $e->ingestUrl);
        self::assertSame('http://other/snap', $e->snapshotUrl);
        self::assertSame('tok.snap', $e->secret);
        self::assertTrue($e->serverless);
        self::assertSame(['mode' => 'hops', 'hops' => 1], $e->trustedProxy);
        self::assertSame('http://localhost:8787/snapshot', Env::resolve(['CAMADA_KEY' => 'a.b', 'CAMADA_INGEST_URL' => 'http://localhost:8787'])?->snapshotUrl);
    }

    public function testEnvIsNullWithoutCredentials(): void
    {
        self::assertNull(Env::resolve([]));
        self::assertNull(Env::resolve(['CAMADA_KEY' => 'nodot']));
        self::assertNull(Env::resolve(['CAMADA_TOKEN' => 'tok']));
    }
}
