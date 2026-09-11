<?php

declare(strict_types=1);

namespace Camada;

/**
 * What an adapter hands the engine. Header names are lower-cased; the list keeps the order
 * the host gave (a hash under FastCGI — getallheaders() — so the analyst reads no HEADER_ORDER
 * signal from this tap).
 */
final class Req
{
    /**
     * @param list<array{string, string}> $headers (lowercased name, value) pairs in host order
     */
    public function __construct(
        public readonly string $method,
        public readonly string $path,                 // no query
        public readonly string $query = '',           // with the leading '?', or ''
        public readonly string $host = '',
        public readonly ?string $httpVersion = null,
        public readonly ?string $peer = null,         // the socket peer the host vouches for
        public readonly bool $https = false,
        public readonly array $headers = [],
        public ?string $route = null,                 // the matched route pattern, when the host knows it at finish time
    ) {
    }

    /**
     * A header the client repeated is joined the way node:http does it: cookies with '; ' (HTTP/2
     * clients split them into several fields; cookieValue() looks for '; name='), the rest with ', '.
     */
    public function header(string $name): ?string
    {
        $vals = [];
        foreach ($this->headers as [$k, $v]) {
            if ($k === $name) {
                $vals[] = $v;
            }
        }
        if ($vals === []) {
            return null;
        }
        return implode($name === 'cookie' ? '; ' : ', ', $vals);
    }
}
