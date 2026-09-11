<?php

declare(strict_types=1);

namespace Camada\Runtime;

use Camada\Guarded;

/**
 * The post-response phase: what a long-lived runtime does on threads, PHP does after the
 * response has left. First the response is ended — fastcgi_finish_request() where it exists
 * (FPM, FrankenPHP; litespeed_finish_request on LiteSpeed), else the fallback for `php -S` and
 * mod_php: the buffer the adapter opened is flushed with a Content-Length so the client can stop
 * reading. Then, in this order: (1) FINISH — the request's event is appended to the spool;
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

    public static function finishResponse(int $obLevel): void
    {
        if (function_exists('fastcgi_finish_request')) {
            fastcgi_finish_request();
            return;
        }
        if (function_exists('litespeed_finish_request')) {
            litespeed_finish_request();
            return;
        }
        if ($obLevel > 0 && ob_get_level() >= $obLevel) {
            while (ob_get_level() > $obLevel) {
                ob_end_flush();
            }
            if (!headers_sent() && self::wantsLength()) {
                header('Content-Length: ' . (int) ob_get_length());
            }
            ob_end_flush();
        }
        flush();
        ignore_user_abort(true);
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
