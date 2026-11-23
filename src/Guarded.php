<?php

declare(strict_types=1);

namespace Camada;

use Camada\Runtime\Lock;

/**
 * The fail-open envelope: a camada bug must never 5xx the customer. Every public entry point of
 * the SDK catches, falls back, and reports through Guarded::log(): at most one line a minute —
 * across every worker, since the minute is kept in a stamp file next to the cache (the mtime of
 * log.stamp) rather than in one process's memory.
 */
final class Guarded
{
    private static ?string $stamp = null;
    private static float $lastLog = 0.0;
    private static ?string $warnStamp = null;
    private static bool $warned = false;

    /** Set the separate shared budgets for errors and configuration warnings. */
    public static function useStamp(?string $path, ?string $warnPath = null): void
    {
        self::$stamp = $path;
        self::$lastLog = 0.0;
        self::$warnStamp = $warnPath;
    }

    public static function warn(string $message): void
    {
        try {
            $stamped = false;
            $stamp = self::$warnStamp;
            // Lock the stamp itself so only one worker can claim an expired budget.
            if ($stamp !== null && ($lock = Lock::acquire($stamp)) !== null) {
                try {
                    $now = time();
                    if ($now - (int) @file_get_contents($stamp) < 3600) {
                        return;
                    }
                    $stamped = @file_put_contents($stamp, (string) $now) !== false;
                } finally {
                    $lock->release();
                }
            }
            if (!$stamped) {
                if (self::$warned) {
                    return;
                }
                self::$warned = true;
            }
            error_log('[camada] config warning: ' . $message);
        } catch (\Throwable) {
            // even logging must not throw
        }
    }

    public static function log(mixed $err): void
    {
        try {
            $now = microtime(true);
            if (self::$stamp !== null) {
                clearstatcache(true, self::$stamp);   // another worker's touch must be seen, not this process's cached stat
            }
            $m = self::$stamp !== null ? @filemtime(self::$stamp) : false;
            if ($m !== false && $now - $m < 60) {
                return;
            }
            if (self::$stamp === null || !@touch(self::$stamp)) {   // no stamp, or one this process cannot write (the cache dir is exactly what the error is about): its own clock
                if ($now - self::$lastLog < 60) {
                    return;
                }
                self::$lastLog = $now;
            }
            error_log('[camada] suppressed error (SDK fails open): ' . self::describe($err));
        } catch (\Throwable) {
            // even logging must not throw
        }
    }

    private static function describe(mixed $err): string
    {
        if ($err instanceof \Throwable) {
            return $err->getMessage() . ' [' . get_class($err) . ' @ ' . $err->getFile() . ':' . $err->getLine() . ']';
        }
        if (is_string($err)) {
            return $err;
        }
        $enc = json_encode($err, JSON_UNESCAPED_SLASHES | JSON_INVALID_UTF8_SUBSTITUTE);
        return $enc === false ? gettype($err) : $enc;
    }
}
