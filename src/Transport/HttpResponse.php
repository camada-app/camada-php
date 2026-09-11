<?php

declare(strict_types=1);

namespace Camada\Transport;

final class HttpResponse
{
    /**
     * @param int $status 0 when the request never got an answer
     * @param array<string, string> $headers lower-cased names
     */
    public function __construct(public readonly int $status, public readonly array $headers, public readonly string $body)
    {
    }
}
