<?php

declare(strict_types=1);

namespace Camada\Snapshot;

/**
 * A section of the container as the matcher reads it: (source, offset, length). Bitmaps are
 * read by index and the range tables are binary-searched, so neither is ever materialised. A
 * section the container omits is a zero-filled slice of the format's default size.
 */
final class Slice
{
    public function __construct(private readonly ?WordSource $src, private readonly int $offset, private readonly int $length)
    {
    }

    public static function zeros(int $n): self
    {
        return new self(null, 0, $n);
    }

    public static function empty(): self
    {
        return new self(null, 0, 0);
    }

    public function get(int $i): int
    {
        return $this->src === null || $i < 0 || $i >= $this->length ? 0 : $this->src->get($this->offset + $i);
    }

    public function length(): int
    {
        return $this->length;
    }

    /** @return list<int> */
    public function toArray(): array
    {
        return $this->src === null ? array_fill(0, $this->length, 0) : $this->src->range($this->offset, $this->length);
    }
}
