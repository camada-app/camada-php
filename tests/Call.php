<?php

declare(strict_types=1);

namespace Camada\Tests;

/** One request through the Driver: what the adapter would have read off the wire. */
final class Call
{
    /** @param list<array{string, string}> $headers */
    public function __construct(
        public readonly string $method = 'GET',
        public readonly string $path = '/',
        public readonly array $headers = [],
        public readonly string $body = '',
        public readonly ?string $peer = '172.16.0.9',   // a peer no golden container lists (10.0.0.0/8 is blocked in all of them)
        public readonly bool $https = false,
        public readonly ?int $contentLength = null,      // override the declared length (null = actual)
    ) {
    }
}
