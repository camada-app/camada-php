<?php

declare(strict_types=1);

namespace Camada\Transport;

final class HttpRequest
{
    /** @param array<string, string> $headers */
    public function __construct(
        public readonly string $method,
        public readonly string $url,
        public readonly array $headers = [],
        public readonly ?string $body = null,
        public readonly float $timeoutS = 3.0,
    ) {
    }
}
