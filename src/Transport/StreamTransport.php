<?php

declare(strict_types=1);

namespace Camada\Transport;

/**
 * file_get_contents over an http stream context: no curl dependency, ignore_errors so a 4xx is
 * an answer rather than a warning, gzip-aware (GET /snapshot ships ~5 MB that gzips to a few KB).
 * The warnings a dead host raises are suppressed: they would otherwise land in the app's log
 * (or its output, under display_errors) for a failure the SDK already fails open on.
 */
final class StreamTransport implements TransportInterface
{
    public function send(HttpRequest $req): HttpResponse
    {
        try {
            $lines = '';
            $seenEncoding = false;
            foreach ($req->headers as $k => $v) {
                $lines .= "{$k}: {$v}\r\n";
                $seenEncoding = $seenEncoding || strtolower($k) === 'accept-encoding';
            }
            if (!$seenEncoding) {
                $lines .= "accept-encoding: gzip\r\n";
            }
            $ctx = stream_context_create(['http' => [
                'method' => $req->method,
                'header' => $lines,
                'content' => $req->body ?? '',
                'timeout' => $req->timeoutS,
                'ignore_errors' => true,
                'follow_location' => 0,
                'protocol_version' => 1.1,
            ]]);
            $body = @file_get_contents($req->url, false, $ctx);
            if ($body === false) {
                return new HttpResponse(0, [], '');
            }
            $raw = self::lastHeaders(get_defined_vars());
            $status = 0;
            $headers = [];
            foreach ($raw as $line) {
                if (preg_match('~^HTTP/\S+\s+(\d{3})~', $line, $m) === 1) {
                    $status = (int) $m[1];
                    $headers = [];   // a later status line (100-continue) restarts the block
                    continue;
                }
                $colon = strpos($line, ':');
                if ($colon !== false) {
                    $headers[substr($line, 0, $colon)] = trim(substr($line, $colon + 1));
                }
            }
            return self::response($status, $headers, $body);
        } catch (\Throwable) {
            return new HttpResponse(0, [], '');
        }
    }

    /**
     * The status/header lines of the last stream request: PHP 8.5 moved them from the magic
     * local `$http_response_header` (deprecated there — even naming it compiles a warning, so
     * older runtimes read it out of the caller's defined variables) to http_get_last_response_headers().
     *
     * @param array<string, mixed> $callerVars
     * @return list<string>
     */
    private static function lastHeaders(array $callerVars): array
    {
        if (function_exists('http_get_last_response_headers')) {
            /** @var list<string>|null $h */
            $h = http_get_last_response_headers();
            return $h ?? [];
        }
        $legacy = $callerVars['http_response_header'] ?? [];
        /** @var list<string> $legacy */
        return $legacy;
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
