<?php

declare(strict_types=1);

namespace Camada\Runtime;

/**
 * The directory one PHP request hands the next. PHP has no long-lived process, so the snapshot,
 * the event spool and the poll state live on disk, shared by every worker of every SAPI:
 * snapshot.bin (the raw BLK container), snapshot.meta.json, state.json, refresh.lock,
 * events.ndjson, events.lock, events.count, flush.json, log.stamp. EVERY write is tmp + rename,
 * so a reader never sees a torn file.
 */
final class Cache
{
    public function __construct(public readonly string $dir)
    {
        if (!is_dir($dir)) {
            @mkdir($dir, 0700, true);
        }
    }

    /** CAMADA_CACHE_DIR, else the system temp dir keyed by the snapshot token (one dir per tenant, never a guessable name). */
    public static function defaultDir(string $snapToken, ?string $override = null): string
    {
        if ($override !== null && $override !== '') {
            return rtrim($override, '/');
        }
        return sys_get_temp_dir() . '/camada-' . substr(hash('sha256', $snapToken), 0, 16);
    }

    public function path(string $name): string
    {
        return $this->dir . '/' . $name;
    }

    public function exists(string $name): bool
    {
        return file_exists($this->path($name));
    }

    public function read(string $name): ?string
    {
        $s = @file_get_contents($this->path($name));
        return $s === false ? null : $s;
    }

    /** @return array<string, mixed>|null a JSON object, or null for anything else (absent, torn, a list) */
    public function readJson(string $name): ?array
    {
        $s = $this->read($name);
        if ($s === null) {
            return null;
        }
        $v = json_decode($s, true);
        if (!is_array($v) || ($v !== [] && array_is_list($v))) {
            return null;
        }
        /** @var array<string, mixed> $v */
        return $v;
    }

    /** tmp + rename: atomic on POSIX, so a concurrent reader sees the old file or the new one, never a torn one. */
    public function write(string $name, string $data): void
    {
        $final = $this->path($name);
        $tmp = $final . '.' . getmypid() . '.' . bin2hex(random_bytes(4)) . '.tmp';
        if (@file_put_contents($tmp, $data) !== strlen($data) || !@rename($tmp, $final)) {
            @unlink($tmp);
            throw new \RuntimeException("camada: cannot write {$final}");
        }
    }

    /** @param array<string, mixed> $data */
    public function writeJson(string $name, array $data): void
    {
        $this->write($name, json_encode($data, JSON_THROW_ON_ERROR | JSON_UNESCAPED_SLASHES));
    }

    public function unlink(string $name): void
    {
        @unlink($this->path($name));
    }
}
