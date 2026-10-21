<?php

declare(strict_types=1);

namespace Camada\Snapshot;

/**
 * One fopen('rb') handle over the cached snapshot.frame (the container starts $offset bytes in, after
 * the meta header; every seek adds it): fseek(4 * i) + unpack('V', fread(4)), with
 * a small read cache so a lookup that revisits a word (the binary searches do) pays once. The
 * handle pins the inode: a concurrent refresh renames a new file into place and this reader
 * keeps seeing the old one whole — never a torn container.
 */
final class FileWords implements WordSource
{
    /** @var array<int, int> */
    private array $cache = [];
    private readonly int $length;

    /**
     * @param resource $fh
     * @param int $offset bytes before the container: 0 for a bare one, 4 + meta-length in a frame
     */
    private function __construct(private $fh, int $bytes, private readonly int $offset = 0)
    {
        $this->length = intdiv($bytes - $offset, 4);
    }

    /**
     * The meta of a frame, [u32 LE meta-len][meta JSON][BLK], and the byte offset its container
     * starts at. $frame need only reach the end of the meta. Shared by the writer (the 200 body)
     * and the reader (snapshot.frame), so both check the one format.
     *
     * @return array{array<string, mixed>, int}
     */
    public static function frameMeta(string $frame): array
    {
        if (strlen($frame) < 4) {
            throw new \RuntimeException('camada: truncated snapshot frame');
        }
        /** @var array{1: int} $len */
        $len = unpack('V', $frame);
        if (4 + $len[1] > strlen($frame)) {
            throw new \RuntimeException('camada: truncated snapshot frame');
        }
        $meta = json_decode(substr($frame, 4, $len[1]), true, 512, JSON_THROW_ON_ERROR);
        if (!is_array($meta)) {
            throw new \RuntimeException('camada: snapshot meta is not an object');
        }
        /** @var array<string, mixed> $meta */
        return [$meta, 4 + $len[1]];
    }

    /**
     * The meta and the container of one snapshot.frame, both read through the one handle so they
     * are one inode: a publish cannot land between them.
     *
     * @return array{array<string, mixed>, self}
     */
    public static function openFrame(string $path): array
    {
        [$fh, $bytes] = self::handle($path);
        try {
            $hdr = (string) fread($fh, 4);
            /** @var array{1: int} $len */
            $len = strlen($hdr) === 4 ? unpack('V', $hdr) : [1 => 0];
            [$meta, $offset] = self::frameMeta($hdr . ($len[1] > 0 ? (string) fread($fh, $len[1]) : ''));
        } catch (\Throwable $err) {
            fclose($fh);
            throw $err;
        }
        return [$meta, new self($fh, $bytes, $offset)];
    }

    public static function open(string $path): self
    {
        return new self(...self::handle($path));
    }

    /** @return array{resource, int} */
    private static function handle(string $path): array
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
        return [$fh, (int) $st['size']];
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
        fseek($this->fh, $this->offset + 4 * $i);
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
        fseek($this->fh, $this->offset + 4 * $offset);
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
