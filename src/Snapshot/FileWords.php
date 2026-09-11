<?php

declare(strict_types=1);

namespace Camada\Snapshot;

/**
 * One fopen('rb') handle over the cached container: fseek(4 * i) + unpack('V', fread(4)), with
 * a small read cache so a lookup that revisits a word (the binary searches do) pays once. The
 * handle pins the inode: a concurrent refresh renames a new file into place and this reader
 * keeps seeing the old one whole — never a torn container.
 */
final class FileWords implements WordSource
{
    /** @var array<int, int> */
    private array $cache = [];
    private readonly int $length;

    /** @param resource $fh */
    private function __construct(private $fh, int $bytes)
    {
        $this->length = intdiv($bytes, 4);
    }

    public static function open(string $path): self
    {
        $fh = @fopen($path, 'rb');
        if ($fh === false) {
            throw new \RuntimeException("camada: cannot open snapshot {$path}");
        }
        $st = fstat($fh);
        if ($st === false) {
            fclose($fh);
            throw new \RuntimeException("camada: cannot stat snapshot {$path}");
        }
        return new self($fh, (int) $st['size']);
    }

    public function get(int $i): int
    {
        if ($i < 0 || $i >= $this->length) {
            return 0;
        }
        if (isset($this->cache[$i])) {
            return $this->cache[$i];
        }
        if (count($this->cache) > 4096) {
            $this->cache = [];   // bounded: one request touches a few dozen words, a long-lived process must not grow forever
        }
        fseek($this->fh, 4 * $i);
        $b = fread($this->fh, 4);
        if ($b === false || strlen($b) !== 4) {
            throw new \RuntimeException('camada: short read on snapshot');
        }
        /** @var array{1: int} $w */
        $w = unpack('V', $b);
        return $this->cache[$i] = $w[1];
    }

    public function length(): int
    {
        return $this->length;
    }

    public function range(int $offset, int $length): array
    {
        if ($length <= 0 || $offset < 0 || $offset + $length > $this->length) {
            return [];
        }
        fseek($this->fh, 4 * $offset);
        $b = fread($this->fh, 4 * $length);
        if ($b === false || strlen($b) !== 4 * $length) {
            throw new \RuntimeException('camada: short read on snapshot');
        }
        /** @var array<int, int> $w */
        $w = unpack("V{$length}", $b);
        return array_values($w);
    }

    public function __destruct()
    {
        fclose($this->fh);
    }
}
