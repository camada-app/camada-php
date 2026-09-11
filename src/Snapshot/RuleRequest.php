<?php

declare(strict_types=1);

namespace Camada\Snapshot;

/**
 * The request a compiled condition reads, built per match() call so one matcher serves every
 * request. `ip6` is the parsed address words, or null.
 *
 * @phpstan-import-type Words from \Camada\IpParse
 */
final class RuleRequest
{
    /**
     * @param Words|null $ip6
     * @param \Closure(string): ?string|null $header called with an already lower-cased name; absent where the tap cannot read headers
     */
    public function __construct(
        public readonly int $n4 = -1,                 // IPv4 as uint32, or -1 when this request has no IPv4 address
        public readonly ?array $ip6 = null,
        public readonly ?int $asn = null,
        public readonly ?string $country = null,
        public readonly ?string $tlsx = null,
        public readonly string $path = '/',           // already query-stripped
        public readonly ?string $ua = null,
        public readonly ?\Closure $header = null,
    ) {
    }
}
