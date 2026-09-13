<?php

declare(strict_types=1);

namespace Camada\Http;

use Camada\Answer;
use Camada\Camada;
use Camada\Context;
use Camada\Guarded;
use Camada\Passed;
use Camada\Req;
use Camada\Runtime\Deferred;

/**
 * The plain-PHP adapter: $_SERVER, php://input and header() alone — FPM, `php -S`, mod_php,
 * any front controller. `Sapi::run($cam)` runs the engine before the app: an Answer is sent and
 * null returned (the script must `return`), else the Context comes back and the app runs with
 * `x-rid` and the `_sfp` cookie already stamped. The post-response phase is a shutdown
 * function: the response is ended first (fastcgi_finish_request under FPM; under `php -S` and
 * mod_php the output buffer run() opened is flushed with a Content-Length so the client can stop
 * reading), then the event is appended, a due spool shipped, a stale snapshot refreshed.
 */
final class Sapi
{
    /** @param array<string, mixed>|null $server the request environment (default: $_SERVER) */
    public static function run(Camada $cam, ?array $server = null): ?Context
    {
        $live = $server === null;
        $server ??= $_SERVER;
        try {
            $req = self::request($server, $live);
            $limit = $cam->wantsBody($req->method, $req->path);
            $body = $limit !== null ? self::body($server, $limit) : null;
        } catch (\Throwable $err) {
            Guarded::log($err);
            return Context::inert();
        }
        $r = $cam->handle($req, $body);
        if ($r instanceof Answer) {
            self::send($r);
            self::install($cam, 0);
            return null;
        }
        return self::pass($cam, $r);
    }

    private static function pass(Camada $cam, Passed $p): Context
    {
        try {
            if ($p->rid !== null) {
                header('x-rid: ' . $p->rid);
            }
            if ($p->setCookie !== null) {
                header('Set-Cookie: ' . $p->setCookie, false);
            }
            $level = 0;
            if ($p->onFinish !== null) {
                $onFinish = $p->onFinish;
                // the app's status is known only at shutdown; an uncaught app exception is PHP's own 500
                $cam->deferred()->arm(Deferred::FINISH, static function () use ($onFinish): void {
                    $status = http_response_code();
                    $onFinish(is_int($status) ? $status : 200);
                });
                if (!function_exists('fastcgi_finish_request') && !function_exists('litespeed_finish_request') && ob_start()) {
                    $level = ob_get_level();   // the fallback finisher flushes this buffer with a Content-Length
                }
            }
            self::install($cam, $level);
        } catch (\Throwable $err) {
            Guarded::log($err);
        }
        return $p->ctx ?? Context::inert();
    }

    private static function install(Camada $cam, int $obLevel): void
    {
        if (!$cam->disabled()) {
            $cam->deferred()->install($obLevel);
        }
    }

    /** Writes an Answer with status, headers and a Content-Length (what a `serveChallenge()` caller does from the app). */
    public static function send(Answer $a): void
    {
        if (!headers_sent()) {
            http_response_code($a->status);
            foreach ($a->headers as [$k, $v]) {
                if ($k === 'content-type' && str_starts_with($v, 'text/') && !str_contains($v, 'charset')) {
                    // PHP appends ";charset=<default_charset>" to a bare text/* type; the contract's 403 is exactly text/plain
                    $prev = ini_set('default_charset', '');
                    header("{$k}: {$v}");
                    ini_set('default_charset', $prev === false ? 'UTF-8' : $prev);
                    continue;
                }
                header("{$k}: {$v}", $k !== 'set-cookie');
            }
            header('Content-Length: ' . strlen($a->body));
        }
        echo $a->body;
    }

    /**
     * The normalised request from the SAPI's view of it. Header order is whatever getallheaders()
     * yields (a hash under FastCGI), so the analyst reads no HEADER_ORDER signal from this tap.
     *
     * @param array<string, mixed> $s
     * @param bool $live read getallheaders() too (the real request; false for a synthetic $s)
     */
    public static function request(array $s, bool $live = false): Req
    {
        $uri = self::str($s['REQUEST_URI'] ?? null) ?? '/';
        $q = strpos($uri, '?');
        $path = $q === false ? $uri : substr($uri, 0, $q);
        $query = self::str($s['QUERY_STRING'] ?? null);
        if ($query === null || $query === '') {
            $query = $q === false ? '' : substr($uri, $q + 1);
        }
        $proto = self::str($s['SERVER_PROTOCOL'] ?? null) ?? '';
        $https = self::str($s['HTTPS'] ?? null);
        return new Req(
            method: self::str($s['REQUEST_METHOD'] ?? null) ?? 'GET',
            path: $path === '' ? '/' : $path,
            query: $query !== '' ? '?' . $query : '',
            host: self::str($s['HTTP_HOST'] ?? null) ?? self::str($s['SERVER_NAME'] ?? null) ?? '',
            httpVersion: str_starts_with($proto, 'HTTP/') ? substr($proto, 5) : null,
            peer: self::str($s['REMOTE_ADDR'] ?? null),
            https: $https !== null && $https !== '' && strtolower($https) !== 'off',
            headers: self::headers($s, $live),
        );
    }

    /**
     * @param array<string, mixed> $s
     * @return list<array{string, string}>
     */
    private static function headers(array $s, bool $live): array
    {
        $out = [];
        $seen = [];
        if ($live && function_exists('getallheaders')) {
            foreach (getallheaders() as $k => $v) {
                $k = strtolower((string) $k);
                $out[] = [$k, (string) $v];
                $seen[$k] = true;
            }
        }
        foreach ($s as $k => $v) {
            if (!is_string($v)) {
                continue;
            }
            if (str_starts_with($k, 'HTTP_')) {
                $name = str_replace('_', '-', strtolower(substr($k, 5)));
            } elseif (($k === 'CONTENT_TYPE' || $k === 'CONTENT_LENGTH') && $v !== '') {
                $name = str_replace('_', '-', strtolower($k));
            } else {
                continue;
            }
            if (!isset($seen[$name])) {
                $out[] = [$name, $v];
                $seen[$name] = true;
            }
        }
        return $out;
    }

    /**
     * At most `$limit` bytes of php://input, or null when the declared or actual size exceeds it.
     * php://input is re-readable, so the app still sees the whole body when the request falls
     * through to it.
     *
     * @param array<string, mixed> $s
     */
    private static function body(array $s, int $limit): ?string
    {
        $declared = (int) (self::str($s['CONTENT_LENGTH'] ?? $s['HTTP_CONTENT_LENGTH'] ?? null) ?? '0');
        if ($declared > $limit) {
            return null;
        }
        $data = file_get_contents('php://input', false, null, 0, max(1, $limit + 1));
        if ($data === false) {
            return '';
        }
        return strlen($data) > $limit ? null : $data;
    }

    private static function str(mixed $v): ?string
    {
        if (is_string($v)) {
            return $v;
        }
        return is_int($v) || is_float($v) ? (string) $v : null;
    }
}
