<?php

declare(strict_types=1);

namespace Camada;

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

    /** The stamp file that keeps the rate limit shared across processes; null falls back to this process's clock. */
    public static function useStamp(?string $path): void
    {
        self::$stamp = $path;
        self::$lastLog = 0.0;
    }

    public static function log(mixed $err): void
    {
        try {
            $now = microtime(true);
            if (self::$stamp !== null) {
                $m = @filemtime(self::$stamp);
                if ($m !== false && $now - $m < 60) {
                    return;
                }
                @touch(self::$stamp);
            } else {
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
