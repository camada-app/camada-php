<?php

declare(strict_types=1);

namespace Camada\Snapshot;

final class MatchResult
{
    public function __construct(
        public readonly bool $block = false,
        public readonly bool $challenge = false,
        public readonly bool $allowed = false,        // true for skip (which absorbed the old allow) and for the allow side
        public readonly bool $warn = false,
        public readonly ?string $action = null,       // the action of the rule that decided, null when a side did
        public readonly ?string $rule = null,         // the rule id, present only when reason is 'rule'
        public readonly ?string $reason = null,       // ip4 | ip6 | asn | country | tls | path | rule | cold
        public readonly ?string $version = null,
    ) {
    }
}
