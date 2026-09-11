<?php

declare(strict_types=1);

namespace Camada\Snapshot;

final class CompiledRule
{
    /** @param list<\Closure(RuleRequest): bool> $conds */
    public function __construct(public readonly string $id, public readonly string $action, public readonly array $conds)
    {
    }
}
