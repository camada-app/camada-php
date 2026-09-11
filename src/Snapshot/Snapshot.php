<?php

declare(strict_types=1);

namespace Camada\Snapshot;

final class Snapshot
{
    /**
     * @param array<string, true> $country
     * @param array<string, true> $tls
     * @param array<string, true> $pathsExact
     * @param array<string, true> $pathsPrefix
     * @param list<string> $pathsRegex compiled PCRE patterns (the ones this runtime accepted)
     * @param list<CompiledRule> $rules v5 only; empty on v3/v4, and the matcher then skips them
     */
    public function __construct(
        public readonly string $version,
        public readonly int $format,          // what the container's version byte claimed
        public readonly Slice $s4,
        public readonly Slice $e4,
        public readonly Slice $idx4,
        public readonly Slice $bm4,
        public readonly Slice $s6,
        public readonly Slice $e6,
        public readonly int $n6,
        public readonly Slice $bm6,
        public readonly Slice $asnBm,
        public readonly Slice $asnExtra,
        public readonly array $country,
        public readonly array $tls,
        public readonly array $pathsExact,
        public readonly array $pathsPrefix,
        public readonly array $pathsRegex,
        public readonly RangeSet $allow,
        public readonly RangeSet $challenge,
        public readonly array $rules,
    ) {
    }
}
