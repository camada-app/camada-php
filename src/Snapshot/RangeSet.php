<?php

declare(strict_types=1);

namespace Camada\Snapshot;

/** A v4 side list, materialised (a side is small). `empty` short-circuits the matcher on the (common) v3 snapshot. */
final class RangeSet
{
    public readonly bool $empty;

    /**
     * @param list<int> $r4 interleaved [start, end]
     * @param list<int> $r6 interleaved [4-word start, 4-word end]
     * @param array<int, true> $asn
     * @param array<string, true> $country
     * @param array<string, true> $pathsExact
     * @param array<string, true> $pathsPrefix
     */
    public function __construct(
        public readonly array $r4,
        public readonly array $r6,
        public readonly array $asn,
        public readonly array $country,
        public readonly array $pathsExact,
        public readonly array $pathsPrefix,
    ) {
        $this->empty = $r4 === [] && $r6 === [] && $asn === [] && $country === [] && $pathsExact === [] && $pathsPrefix === [];
    }

    public function n6(): int
    {
        return count($this->r6) >> 3;
    }
}
