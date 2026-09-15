<?php

declare(strict_types=1);

namespace Camada\Transport;

/**
 * A minimal HTTP/1.1 client over a plain (or TLS) stream socket: no curl dependency, a 4xx is
 * an answer rather than a warning, gzip-aware (GET /snapshot ships ~5 MB that gzips to a few KB).
 *
 * It is deliberately not file_get_contents over the http:// wrapper: that wrapper reads until the
 * server closes the socket, and a keep-alive server (wrangler dev answers chunked and idle-closes
 * seconds later) then holds every enforcement for the whole idle timeout. This client asks for
 * `Connection: close` and, either way, stops reading the moment the body is complete: at
 * Content-Length, or at the terminating chunk of a chunked body.
 *
 * The warnings a dead host raises are suppressed: they would otherwise land in the app's log
 * (or its output, under display_errors) for a failure the SDK already fails open on.
 */
final class StreamTransport implements TransportInterface
{
    private const READ = 65536;

    public function send(HttpRequest $req): HttpResponse
    {
        try {
            return $this->exchange($req) ?? new HttpResponse(0, [], '');
        } catch (\Throwable) {
            return new HttpResponse(0, [], '');
        }
    }

    private function exchange(HttpRequest $req): ?HttpResponse
    {
        $parts = parse_url($req->url);
        if (!is_array($parts) || !isset($parts['host'])) {
            return null;
        }
        $scheme = strtolower($parts['scheme'] ?? 'http');
        if ($scheme !== 'http' && $scheme !== 'https') {
            return null;
        }
        $host = $parts['host'];
        $port = $parts['port'] ?? ($scheme === 'https' ? 443 : 80);
        $path = ($parts['path'] ?? '') === '' ? '/' : $parts['path'];
        if (isset($parts['query'])) {
            $path .= '?' . $parts['query'];
        }
        $hostHeader = $host . ($port === ($scheme === 'https' ? 443 : 80) ? '' : ":{$port}");

        $deadline = microtime(true) + $req->timeoutS;
        $ctx = stream_context_create(['ssl' => ['peer_name' => $host, 'SNI_enabled' => true]]);
        $sock = @stream_socket_client(
            ($scheme === 'https' ? 'ssl' : 'tcp') . "://{$host}:{$port}",
            $errno,
            $errstr,
            max(0.001, $req->timeoutS),
            STREAM_CLIENT_CONNECT,
            $ctx,
        );
        if ($sock === false) {
            return null;
        }
        try {
            $seen = [];
            $head = "{$req->method} {$path} HTTP/1.1\r\nHost: {$hostHeader}\r\n";
            foreach ($req->headers as $k => $v) {
                $seen[strtolower($k)] = true;
                $head .= "{$k}: {$v}\r\n";
            }
            if (!isset($seen['accept-encoding'])) {
                $head .= "Accept-Encoding: gzip\r\n";
            }
            if (!isset($seen['connection'])) {
                $head .= "Connection: close\r\n";
            }
            $body = $req->body ?? '';
            if ($body !== '' || ($req->method !== 'GET' && $req->method !== 'HEAD')) {
                if (!isset($seen['content-length'])) {
                    $head .= 'Content-Length: ' . strlen($body) . "\r\n";
                }
            }
            $wire = $head . "\r\n" . $body;
            while ($wire !== '') {
                if (!self::arm($sock, $deadline)) {
                    return null;
                }
                $n = @fwrite($sock, $wire);
                if ($n === false || $n === 0) {
                    return null;
                }
                $wire = substr($wire, $n);
            }

            $raw = '';
            while (($split = strpos($raw, "\r\n\r\n")) === false) {
                $chunk = self::read($sock, $deadline);
                if ($chunk === null) {
                    return null;
                }
                $raw .= $chunk;
            }
            [$status, $headers] = self::parseHead(substr($raw, 0, $split));
            $rest = substr($raw, $split + 4);
            while ($status === 100) {   // 100-continue: the real answer follows on the same socket
                $raw = $rest;
                while (($split = strpos($raw, "\r\n\r\n")) === false) {
                    $chunk = self::read($sock, $deadline);
                    if ($chunk === null) {
                        return null;
                    }
                    $raw .= $chunk;
                }
                [$status, $headers] = self::parseHead(substr($raw, 0, $split));
                $rest = substr($raw, $split + 4);
            }
            if ($status === 0) {
                return null;
            }
            $lower = [];
            foreach ($headers as $k => $v) {
                $lower[strtolower($k)] = $v;
            }
            $noBody = $req->method === 'HEAD' || $status === 204 || $status === 304;
            if ($noBody) {
                $out = '';
            } elseif (str_contains(strtolower($lower['transfer-encoding'] ?? ''), 'chunked')) {
                $out = self::dechunk($sock, $rest, $deadline);
                if ($out === null) {
                    return null;
                }
                unset($lower['transfer-encoding']);
            } elseif (isset($lower['content-length']) && is_numeric($lower['content-length'])) {
                $length = (int) $lower['content-length'];
                $out = $rest;
                while (strlen($out) < $length) {
                    $chunk = self::read($sock, $deadline);
                    if ($chunk === null) {
                        return null;
                    }
                    $out .= $chunk;
                }
                $out = substr($out, 0, $length);
            } else {
                $out = $rest;   // no framing: the body ends when the server closes
                while (($chunk = self::read($sock, $deadline)) !== null) {
                    $out .= $chunk;
                }
                if (!feof($sock)) {
                    return null;   // timed out, not closed
                }
            }
            return self::response($status, $lower, $out);
        } finally {
            @fclose($sock);
        }
    }

    /**
     * Reads the chunks of a chunked body up to its terminating chunk; trailers are discarded.
     * Returns null on a framing error or a timeout, so a half-answer is no answer.
     */
    private static function dechunk(mixed $sock, string $buf, float $deadline): ?string
    {
        $out = '';
        while (true) {
            while (($eol = strpos($buf, "\r\n")) === false) {
                $chunk = self::read($sock, $deadline);
                if ($chunk === null) {
                    return null;
                }
                $buf .= $chunk;
            }
            $sizeLine = trim(substr($buf, 0, $eol));
            $semi = strpos($sizeLine, ';');
            $hex = $semi === false ? $sizeLine : substr($sizeLine, 0, $semi);
            if ($hex === '' || !ctype_xdigit($hex)) {
                return null;
            }
            $size = (int) hexdec($hex);
            $buf = substr($buf, $eol + 2);
            if ($size === 0) {
                return $out;   // the terminating chunk: whatever follows (trailers, CRLF) is not ours to wait for
            }
            while (strlen($buf) < $size + 2) {
                $chunk = self::read($sock, $deadline);
                if ($chunk === null) {
                    return null;
                }
                $buf .= $chunk;
            }
            $out .= substr($buf, 0, $size);
            $buf = substr($buf, $size + 2);
        }
    }

    /**
     * One read within the deadline: null on timeout, EOF or error.
     *
     * @param resource $sock
     */
    private static function read(mixed $sock, float $deadline): ?string
    {
        if (!self::arm($sock, $deadline)) {
            return null;
        }
        $chunk = @fread($sock, self::READ);
        if ($chunk === false || $chunk === '') {
            return null;
        }
        return $chunk;
    }

    /**
     * Points the socket's own timeout at what is left of the deadline; false once it has passed.
     *
     * @param resource $sock
     */
    private static function arm(mixed $sock, float $deadline): bool
    {
        $left = $deadline - microtime(true);
        if ($left <= 0) {
            return false;
        }
        $sec = (int) floor($left);
        stream_set_timeout($sock, $sec, (int) (($left - $sec) * 1_000_000));
        return true;
    }

    /**
     * @return array{int, array<string, string>}
     */
    private static function parseHead(string $head): array
    {
        $status = 0;
        $headers = [];
        foreach (explode("\r\n", $head) as $i => $line) {
            if ($i === 0) {
                if (preg_match('~^HTTP/\S+\s+(\d{3})~', $line, $m) === 1) {
                    $status = (int) $m[1];
                }
                continue;
            }
            $colon = strpos($line, ':');
            if ($colon !== false) {
                $headers[substr($line, 0, $colon)] = trim(substr($line, $colon + 1));
            }
        }
        return [$status, $headers];
    }

    /**
     * Lower-cases the names and undoes a gzip body; one it cannot read is no answer at all.
     *
     * @param array<string, string> $headers
     */
    public static function response(int $status, array $headers, string $body): HttpResponse
    {
        $lower = [];
        foreach ($headers as $k => $v) {
            $lower[strtolower($k)] = $v;
        }
        if (strtolower($lower['content-encoding'] ?? '') === 'gzip') {
            $plain = @gzdecode($body);
            if ($plain === false) {
                return new HttpResponse(0, $lower, '');
            }
            unset($lower['content-encoding']);
            $body = $plain;
        }
        return new HttpResponse($status, $lower, $body);
    }
}
