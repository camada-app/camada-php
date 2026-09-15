<?php

declare(strict_types=1);

namespace Camada\Tests;

use Camada\Guarded;
use Camada\Transport\HttpRequest;
use Camada\Transport\StreamTransport;
use PHPUnit\Framework\TestCase;

/**
 * The one HTTP seam: file_get_contents over an http stream context, gzip-aware, never throws
 * (a network failure is a status-0 response every caller treats as "keep what we have").
 * Plus the fail-open envelope's rate-limited log line.
 */
final class TransportTest extends TestCase
{
    public function testStreamTransportGunzipsAndReadsHeaders(): void
    {
        $srv = new PhpServer(__DIR__ . '/fixtures/gzip-server.php');
        try {
            $t = new StreamTransport();
            $r = $t->send(new HttpRequest('GET', $srv->url . '/snapshot', ['accept-encoding' => 'gzip'], null, 2.0));
            self::assertSame(200, $r->status);
            $meta = (string) json_encode(['version' => 'z']);
            self::assertSame(pack('V', strlen($meta)) . $meta . 'BLK', $r->body);
            self::assertSame('"z"', $r->headers['etag']);
            self::assertSame('{"beacon":true}', $r->headers['x-camada-config']);
            self::assertArrayNotHasKey('content-encoding', $r->headers);
            $post = $t->send(new HttpRequest('POST', $srv->url . '/e', ['x-tenant' => 'tok', 'content-type' => 'application/json'], '[{"a":1},{"b":2}]', 2.0));
            self::assertSame(202, $post->status);
            self::assertSame(['n' => 2, 'tenant' => 'tok'], json_decode($post->body, true));
            self::assertSame(404, $t->send(new HttpRequest('GET', $srv->url . '/nope', [], null, 2.0))->status);   // ignore_errors: a 4xx is an answer, not a throw
        } finally {
            $srv->stop();
        }
    }

    /**
     * wrangler dev answers chunked over keep-alive and idle-closes seconds later; the transport
     * must return the moment the body is complete (terminating chunk, or Content-Length reached),
     * not when the server finally hangs up.
     */
    public function testReturnsAsSoonAsTheBodyIsCompleteOnAKeepAliveSocket(): void
    {
        $port = PhpServer::freePort();
        $proc = proc_open([PHP_BINARY, __DIR__ . '/fixtures/lingering-server.php', (string) $port], [1 => ['pipe', 'w'], 2 => ['pipe', 'w']], $pipes);
        self::assertIsResource($proc);
        try {
            self::assertSame("started\n", fgets($pipes[1]));
            $t = new StreamTransport();
            foreach (['/chunked', '/length'] as $path) {
                $t0 = microtime(true);
                $r = $t->send(new HttpRequest('GET', "http://127.0.0.1:{$port}{$path}", [], null, 5.0));
                $ms = (microtime(true) - $t0) * 1000;
                self::assertSame(200, $r->status, $path);
                self::assertSame(['path' => $path, 'keepalive' => true], json_decode($r->body, true), $path);
                self::assertArrayNotHasKey('transfer-encoding', $r->headers);
                self::assertLessThan(1000, $ms, "{$path} waited for the server's idle close ({$ms} ms)");
            }
        } finally {
            proc_terminate($proc, SIGKILL);
            fclose($pipes[1]);
            fclose($pipes[2]);
            proc_close($proc);
        }
    }

    public function testADeadHostIsStatusZeroWithoutAWarning(): void
    {
        $port = PhpServer::freePort();
        set_error_handler(static function (int $no, string $msg): bool {
            throw new \RuntimeException("a warning surfaced: {$msg}");
        });
        try {
            $r = (new StreamTransport())->send(new HttpRequest('GET', "http://127.0.0.1:{$port}/snapshot", [], null, 0.5));
        } finally {
            restore_error_handler();
        }
        self::assertSame(0, $r->status);
        self::assertSame('', $r->body);
    }

    public function testAnUndecodableGzipBodyIsNoAnswerAtAll(): void
    {
        $r = StreamTransport::response(200, ['Content-Encoding' => 'gzip', 'ETag' => '"x"'], 'not gzip');
        self::assertSame(0, $r->status);
        self::assertSame('"x"', $r->headers['etag']);   // names are lower-cased
    }

    public function testGuardedLogsAtMostOnceAMinute(): void
    {
        $dir = sys_get_temp_dir() . '/camada-guarded-' . getmypid() . '-' . random_int(1, 1_000_000);
        mkdir($dir);
        $log = $dir . '/error.log';
        $prev = ini_set('error_log', $log);
        Guarded::useStamp($dir . '/log.stamp');
        try {
            Guarded::log(new \RuntimeException('first'));
            Guarded::log('second');
            $lines = file($log, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);
            self::assertIsArray($lines);
            self::assertCount(1, $lines);
            self::assertStringContainsString('[camada] suppressed error (SDK fails open): first', $lines[0]);
            touch($dir . '/log.stamp', time() - 61);
            Guarded::log('third');
            $lines = file($log, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);
            self::assertIsArray($lines);
            self::assertCount(2, $lines);
            self::assertStringContainsString('third', $lines[1]);
        } finally {
            Guarded::useStamp(null);
            ini_set('error_log', $prev === false ? '' : $prev);
            @unlink($log);
            @unlink($dir . '/log.stamp');
            @rmdir($dir);
        }
    }
}
