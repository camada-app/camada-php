<?php

declare(strict_types=1);

namespace Camada\Tests;

/** What the Driver answered: status, headers as sent, body. */
final class Reply
{
    /** @param list<array{string, string}> $headers */
    public function __construct(public readonly int $status, public readonly array $headers, public readonly string $body)
    {
    }

    public function header(string $name): ?string
    {
        foreach ($this->headers as [$k, $v]) {
            if (strtolower($k) === $name) {
                return $v;
            }
        }
        return null;
    }

    /** @return list<string> */
    public function headersNamed(string $name): array
    {
        $out = [];
        foreach ($this->headers as [$k, $v]) {
            if (strtolower($k) === $name) {
                $out[] = $v;
            }
        }
        return $out;
    }
}
