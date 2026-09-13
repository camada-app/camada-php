<?php

declare(strict_types=1);

namespace Camada\Laravel;

use Camada\Answer;
use Camada\Camada;
use Camada\Context;
use Camada\Guarded;
use Camada\Http\Sapi;
use Camada\Passed;
use Illuminate\Http\Request;
use Illuminate\Http\Response;
use Symfony\Component\HttpFoundation\Response as SymfonyResponse;

/**
 * Laravel middleware: put it first in the global stack so camada answers before anything else
 * runs. handle() runs the engine and stamps the response; terminate() is the post-response phase
 * (the kernel calls it after Response::send(), which has already ended the response under FPM).
 * The Context rides `$request->attributes->get('camada')` for `scriptTag()`, `track()` and
 * `serveChallenge()`; `Camada::default()` is the engine unless one is handed in.
 */
final class Middleware
{
    private const CTX = 'camada';
    private const PASSED = 'camada.passed';

    private ?Camada $engine;

    public function __construct(?Camada $engine = null)
    {
        $this->engine = $engine;
    }

    public function engine(): Camada
    {
        return $this->engine ??= Camada::default();
    }

    /** @param \Closure(Request): SymfonyResponse $next */
    public function handle(Request $request, \Closure $next): SymfonyResponse
    {
        $eng = $this->engine();
        try {
            $req = Sapi::request($request->server->all());
            $req = new \Camada\Req(
                method: $request->getMethod(),
                path: $request->getPathInfo(),
                query: $req->query,
                host: $request->getHttpHost(),
                httpVersion: $req->httpVersion,
                peer: $request->server->get('REMOTE_ADDR'),
                https: $request->isSecure(),
                headers: $req->headers,
            );
            $limit = $eng->wantsBody($req->method, $req->path);
            $body = $limit !== null ? self::body($request, $limit) : null;
        } catch (\Throwable $err) {
            Guarded::log($err);
            return $next($request);
        }
        $result = $eng->handle($req, $body);
        if ($result instanceof Answer) {
            $eng->deferred()->runTasks();   // the answer's row is spooled; ship and refresh ride terminate() otherwise
            return self::answer($result);
        }
        $request->attributes->set(self::CTX, $result->ctx ?? Context::inert());
        $request->attributes->set(self::PASSED, $result);
        try {
            $response = $next($request);
        } catch (\Throwable $e) {
            $this->finish($request, 500);   // the app threw: the framework will answer 500
            throw $e;
        }
        try {
            if ($result->rid !== null) {
                $response->headers->set('x-rid', $result->rid);
            }
            if ($result->setCookie !== null) {
                $response->headers->set('set-cookie', $result->setCookie, false);
            }
        } catch (\Throwable $err) {
            Guarded::log($err);
        }
        return $response;
    }

    /** The post-response phase: the event, a due spool, a stale snapshot — once per request. */
    public function terminate(Request $request, SymfonyResponse $response): void
    {
        $this->finish($request, $response->getStatusCode());
    }

    private function finish(Request $request, int $status): void
    {
        $p = $request->attributes->get(self::PASSED);
        $request->attributes->remove(self::PASSED);
        if ($p instanceof Passed && $p->onFinish !== null) {
            try {
                /** @var mixed $route the matched Illuminate\Routing\Route, when the router ran (illuminate/routing is not a dependency) */
                $route = $request->route();
                if ($p->ctx?->req !== null && is_object($route) && method_exists($route, 'uri')) {
                    /** @var mixed $uri */
                    $uri = $route->uri();
                    $p->ctx->req->route = is_string($uri) && $uri !== '' ? '/' . ltrim($uri, '/') : null;
                }
            } catch (\Throwable $err) {
                Guarded::log($err);
            }
            ($p->onFinish)($status);
        }
        $this->engine()->deferred()->runTasks();
    }

    private static function body(Request $request, int $limit): ?string
    {
        $declared = (int) $request->server->get('CONTENT_LENGTH', $request->headers->get('content-length', '0'));
        if ($declared > $limit) {
            return null;
        }
        $data = $request->getContent();
        return strlen($data) > $limit ? null : $data;
    }

    private static function answer(Answer $a): Response
    {
        $r = new Response($a->body, $a->status);
        $r->headers->remove('content-type');   // camada's answers name their own type, or none (a 302, a 204, a 413)
        foreach ($a->headers as [$k, $v]) {
            $r->headers->set($k, $v, $k !== 'set-cookie');
        }
        return $r;
    }
}
