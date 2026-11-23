<?php

declare(strict_types=1);

namespace Camada\Events;

final class RowOptions
{
    /** @param (\Closure(string): ?string)|null $tokenHasher */
    public function __construct(
        public readonly ?string $tokenHeader = null,
        public readonly ?\Closure $tokenHasher = null,
        public readonly string|false $progressName = false,
    ) {
    }
}
