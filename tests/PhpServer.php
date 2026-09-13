<?php

declare(strict_types=1);

namespace Camada\Tests;

use PHPUnit\Framework\Assert;

/**
 * A `php -S` subprocess for the tests that need a real HTTP hop (the stream transport, the
 * SAPI adapter): started on a free port with a router script and an environment, stopped
 * (process group and all) when the test is done.
 */
final class PhpServer
{
    /** @var resource */
    private $proc;
    public readonly string $url;
    public readonly int $port;
    private string $out = '';
    /** @var array<int, resource> */
    private array $pipes;

    /** @param array<string, string> $env */
    public function __construct(string $router, array $env = [], string $docRoot = '', int $workers = 1)
    {
        $this->port = self::freePort();
        $this->url = "http://127.0.0.1:{$this->port}";
        $cmd = [PHP_BINARY, '-S', "127.0.0.1:{$this->port}", '-d', 'display_errors=stderr', '-d', 'error_reporting=E_ALL'];
        if ($docRoot !== '') {
            array_push($cmd, '-t', $docRoot);
        }
        $cmd[] = $router;
        $fullEnv = array_merge(self::inheritedEnv(), $env);
        unset($fullEnv['PHP_CLI_SERVER_WORKERS']);
        if ($workers > 1) {   // the CLI server refuses a worker count of 1: unset means single-process
            $fullEnv['PHP_CLI_SERVER_WORKERS'] = (string) $workers;
        }
        $proc = proc_open($cmd, [1 => ['pipe', 'w'], 2 => ['pipe', 'w']], $pipes, null, $fullEnv);
        Assert::assertIsResource($proc, 'php -S did not start');
        $this->proc = $proc;
        $this->pipes = $pipes;
        stream_set_blocking($pipes[1], false);
        stream_set_blocking($pipes[2], false);
        // readiness is the server's own "started" line: a bare TCP probe (an empty preconnection) wedges
        // the single-process CLI server on the connection after it, and an HTTP probe would be a first request
        $deadline = microtime(true) + 10;
        while (microtime(true) < $deadline) {
            if (str_contains($this->output(), ') started')) {
                return;
            }
            if (!proc_get_status($proc)['running']) {
                break;
            }
            usleep(20_000);
        }
        Assert::fail("php -S never started on :{$this->port}\n" . $this->output());
    }

    /** @return array<string, string> */
    private static function inheritedEnv(): array
    {
        return getenv();
    }

    public static function freePort(): int
    {
        $s = stream_socket_server('tcp://127.0.0.1:0');
        Assert::assertNotFalse($s);
        $name = stream_socket_get_name($s, false);
        fclose($s);
        Assert::assertIsString($name);
        return (int) substr($name, (int) strrpos($name, ':') + 1);
    }

    /** Everything the server wrote to stdout/stderr so far (a crash, a warning, a camada log line). */
    public function output(): string
    {
        foreach ([1, 2] as $i) {
            $more = stream_get_contents($this->pipes[$i]);
            if (is_string($more)) {
                $this->out .= $more;
            }
        }
        return $this->out;
    }

    /**
     * A raw HTTP/1.1 client that stops reading at Content-Length: PHP's own http:// wrapper reads
     * until the server closes, which under php -S is only when the script — post-response phase
     * included — has ended, so it could never show that the response ended first.
     *
     * @param array<string, string> $headers
     * @return array{status: int, headers: array<string, list<string>>, body: string, ms: float}
     * @phpstan-impure
     */
    public function request(string $method, string $path, array $headers = [], ?string $body = null): array
    {
        $t0 = microtime(true);
        $sock = @stream_socket_client("tcp://127.0.0.1:{$this->port}", $errno, $errstr, 10);
        Assert::assertIsResource($sock, "no connection to php -S for {$method} {$path}: {$errstr}\n" . $this->output());
        stream_set_timeout($sock, 10);
        $head = "{$method} {$path} HTTP/1.1\r\nHost: 127.0.0.1:{$this->port}\r\nConnection: close\r\n";
        foreach ($headers as $k => $v) {
            $head .= "{$k}: {$v}\r\n";
        }
        if ($body !== null) {
            $head .= 'Content-Length: ' . strlen($body) . "\r\n";
        }
        fwrite($sock, $head . "\r\n" . ($body ?? ''));
        $raw = '';
        while (!str_contains($raw, "\r\n\r\n")) {
            $chunk = fread($sock, 8192);
            if ($chunk === false || $chunk === '') {
                break;
            }
            $raw .= $chunk;
        }
        $split = strpos($raw, "\r\n\r\n");
        Assert::assertIsInt($split, "no answer from php -S for {$method} {$path}\n" . $this->output());
        $out = substr($raw, $split + 4);
        $status = 0;
        $parsed = [];
        foreach (explode("\r\n", substr($raw, 0, $split)) as $line) {
            if (preg_match('~^HTTP/\S+ (\d{3})~', $line, $m) === 1) {
                $status = (int) $m[1];
                continue;
            }
            $colon = strpos($line, ':');
            if ($colon !== false) {
                $parsed[strtolower(substr($line, 0, $colon))][] = trim(substr($line, $colon + 1));
            }
        }
        $length = isset($parsed['content-length'][0]) ? (int) $parsed['content-length'][0] : null;
        while ($length === null || strlen($out) < $length) {
            $chunk = fread($sock, 65536);
            if ($chunk === false || $chunk === '') {
                break;
            }
            $out .= $chunk;
        }
        fclose($sock);
        if ($length !== null) {
            $out = substr($out, 0, $length);
        }
        $ms = (microtime(true) - $t0) * 1000;
        return ['status' => $status, 'headers' => $parsed, 'body' => $out, 'ms' => $ms];
    }

    public function stop(): void
    {
        $status = proc_get_status($this->proc);
        if ($status['running']) {
            // the CLI server forks its workers and they outlive a terminated master: end them first
            foreach (explode("\n", trim((string) shell_exec("pgrep -P {$status['pid']}"))) as $child) {
                if ($child !== '') {
                    posix_kill((int) $child, SIGKILL);
                }
            }
            posix_kill(-$status['pid'], SIGTERM);
            proc_terminate($this->proc, SIGTERM);
        }
        $this->output();
        foreach ($this->pipes as $p) {
            fclose($p);
        }
        proc_close($this->proc);
    }
}
