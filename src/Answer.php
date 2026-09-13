<?php

declare(strict_types=1);

namespace Camada;

/**
 * camada answered the request; the adapter writes exactly this (a block, the challenge page,
 * the verify redirect, the beacon endpoints).
 */
final class Answer
{
    /** @param list<array{string, string}> $headers (lowercased name, value) pairs */
    public function __construct(
        public readonly int $status,
        public readonly array $headers,
        public readonly string $body,
    ) {
    }
}
