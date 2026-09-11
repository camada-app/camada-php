<?php

declare(strict_types=1);

namespace Camada\Snapshot;

final class MemoryWords implements WordSource
{
    private readonly int $length;

    public function __construct(private readonly string $bytes)
    {
        $this->length = intdiv(strlen($bytes), 4);
    }

    public function get(int $i): int
    {
        if ($i < 0 || $i >= $this->length) {
            return 0;
        }
        /** @var array{1: int} $w */
        $w = unpack('V', $this->bytes, 4 * $i);
        return $w[1];
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
        /** @var array<int, int> $w */
        $w = unpack("V{$length}", $this->bytes, 4 * $offset);
        return array_values($w);
    }
}
