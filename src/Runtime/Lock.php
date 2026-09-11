<?php

declare(strict_types=1);

namespace Camada\Runtime;

/**
 * flock() over a lock file: what keeps one refresh, one ship and one spool append in flight
 * across workers. Non-blocking for the post-response work (a busy lock means another worker is
 * on it: yield), blocking only for the brief spool append.
 */
final class Lock
{
    /** @param resource|null $fh */
    private function __construct(private $fh)
    {
    }

    /** @phpstan-impure */
    public static function tryAcquire(string $path): ?self
    {
        return self::open($path, false);
    }

    /** @phpstan-impure */
    public static function acquire(string $path): ?self
    {
        return self::open($path, true);
    }

    private static function open(string $path, bool $blocking): ?self
    {
        $fh = @fopen($path, 'c');
        if ($fh === false) {
            return null;
        }
        if (!@flock($fh, $blocking ? LOCK_EX : LOCK_EX | LOCK_NB)) {
            fclose($fh);
            return null;
        }
        return new self($fh);
    }

    public function release(): void
    {
        if ($this->fh !== null) {
            @flock($this->fh, LOCK_UN);
            fclose($this->fh);
            $this->fh = null;
        }
    }

    public function __destruct()
    {
        $this->release();
    }
}
