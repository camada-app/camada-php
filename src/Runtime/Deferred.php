<?php

declare(strict_types=1);

namespace Camada\Runtime;

use Camada\Guarded;

/**
 * The post-response phase: what a long-lived runtime does on threads, PHP does after the
 * response has left. First the response is ended — fastcgi_finish_request() where it exists
 * (FPM, FrankenPHP; litespeed_finish_request on LiteSpeed), else the fallback for `php -S` and
 * mod_php: every output buffer is ended (the adapter's, with a Content-Length stamped first, and
 * the SAPI's own) so the client can stop reading. Then, in this order: (1) FINISH — the request's event is appended to the spool;
 * (2) SHIP — a due spool is POSTed; (3) REFRESH — a stale snapshot is polled. Each slot is armed
 * at most once per request (the first arm wins) and runs inside the fail-open envelope.
 */
final class Deferred
{
    public const FINISH = 0;
    public const SHIP = 1;
    public const REFRESH = 2;

    /** @var array<int, \Closure(): void> */
    private array $tasks = [];
    private bool $installed = false;
    private int $obLevel = 0;

    public function __construct(private readonly bool $register = true)
    {
    }

    /** @param \Closure(): void $task */
    public function arm(int $slot, \Closure $task): void
    {
        $this->tasks[$slot] ??= $task;
    }

    public function armed(int $slot): bool
    {
        return isset($this->tasks[$slot]);
    }

    /** Registers run() as the shutdown function, once. `$obLevel` is the output buffer the adapter opened (0: none). */
    public function install(int $obLevel = 0): void
    {
        if ($this->installed) {
            return;
        }
        $this->installed = true;
        $this->obLevel = $obLevel;
        if ($this->register) {
            register_shutdown_function($this->run(...));
        }
    }

    public function installed(): bool
    {
        return $this->installed;
    }

    /** The shutdown function: end the response, then the deferred work. */
    public function run(): void
    {
        try {
            self::finishResponse($this->obLevel);
        } catch (\Throwable $e) {
            Guarded::log($e);
        }
        $this->runTasks();
    }

    /** The deferred work alone, in slot order (what a host that already ended its response calls). */
    public function runTasks(): void
    {
        $tasks = $this->tasks;
        $this->tasks = [];
        foreach ([self::FINISH, self::SHIP, self::REFRESH] as $slot) {
            if (!isset($tasks[$slot])) {
                continue;
            }
            try {
                $tasks[$slot]();
            } catch (\Throwable $e) {
                Guarded::log($e);
            }
        }
    }

    /**
     * Ends the response. `$obLevel` is the output buffer the adapter opened around the app (0: none —
     * the adapter already sent an Answer with its Content-Length).
     */
    public static function finishResponse(int $obLevel): void
    {
        self::fatalIs500();
        if (function_exists('fastcgi_finish_request')) {
            fastcgi_finish_request();
            return;
        }
        if (function_exists('litespeed_finish_request')) {
            litespeed_finish_request();
            return;
        }
        // The fallback (php -S, mod_php): end EVERY output buffer — the adapter's and the SAPI's own
        // (output_buffering=4096 under the CLI server, which flush() never drains) — with a
        // Content-Length stamped first, so the client can stop reading before the deferred work runs.
        if ($obLevel > 0 && ob_get_level() >= $obLevel) {
            while (ob_get_level() > 1) {
                ob_end_flush();
            }
            if (!headers_sent() && self::wantsLength()) {
                header('Content-Length: ' . (int) ob_get_length());
            }
        }
        while (ob_get_level() > 0) {
            ob_end_flush();
        }
        flush();
        ignore_user_abort(true);
    }

    /**
     * An uncaught exception or fatal error in the app is PHP's own 500 — PHP stamps it itself only
     * with display_errors off, so the fallback does it whenever the headers are still unsent: the
     * client and the event both see the status the app really ended with.
     */
    private static function fatalIs500(): void
    {
        $e = error_get_last();
        if ($e === null || !in_array($e['type'], [E_ERROR, E_PARSE, E_CORE_ERROR, E_COMPILE_ERROR, E_USER_ERROR, E_RECOVERABLE_ERROR], true)) {
            return;
        }
        if (!headers_sent() && http_response_code() === 200) {
            http_response_code(500);
        }
    }

    private static function wantsLength(): bool
    {
        $status = http_response_code();
        if ($status === 204 || $status === 304 || ($_SERVER['REQUEST_METHOD'] ?? '') === 'HEAD') {
            return false;
        }
        foreach (headers_list() as $h) {
            $lower = strtolower($h);
            if (str_starts_with($lower, 'content-length:') || str_starts_with($lower, 'transfer-encoding:')) {
                return false;
            }
        }
        return true;
    }
}
