<?php

declare(strict_types=1);

namespace Camada\Snapshot;

final class MatchInput
{
    /**
     * @param \Closure(string): ?string|null $header v5 header conditions read it, always with a lower-cased name
     */
    public function __construct(
        public readonly ?string $ip = null,
        public readonly ?int $asn = null,
        public readonly ?string $country = null,
        public readonly ?string $tlsx = null,
        public readonly ?string $path = null,
        public readonly ?string $ua = null,          // v5 rules read it; the three sides never do
        public readonly ?\Closure $header = null,
    ) {
    }
}
