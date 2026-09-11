<?php

declare(strict_types=1);

namespace Camada\Snapshot;

/**
 * A BLK container read as little-endian uint32 words. Two implementations: the whole container
 * in a string (MemoryWords) and a seeking reader over the cached snapshot.bin (FileWords) — the
 * per-request path never materialises the ~5 MB, it seeks the few dozen words a lookup touches.
 */
interface WordSource
{
    /** The word at index $i (0 when past the end). */
    public function get(int $i): int;

    /** Word count (a trailing partial word is dropped, as a Uint32Array view does). */
    public function length(): int;

    /**
     * $length consecutive words from $offset, materialised (the header and the small sections).
     *
     * @return list<int>
     */
    public function range(int $offset, int $length): array;
}
