<?php

declare(strict_types=1);

namespace Camada;

/**
 * Run the app. `rid` and `setCookie` ride the response; `ctx` is what the host stores for the
 * app (Sapi::run() returns it, the Laravel middleware puts it in the request attributes);
 * `onFinish(status)` is called exactly once when the response is done — in the post-response
 * phase under a SAPI — and appends the request's wire event to the spool. The inert Passed
 * (every field null) is what a disabled, unconfigured or broken engine hands back: the app runs
 * untouched.
 */
final class Passed
{
    /** @param (\Closure(int): void)|null $onFinish */
    public function __construct(
        public readonly ?string $rid = null,
        public readonly ?string $setCookie = null,
        public readonly ?Context $ctx = null,
        public readonly ?\Closure $onFinish = null,
    ) {
    }

    public static function inert(): self
    {
        return new self();
    }
}
