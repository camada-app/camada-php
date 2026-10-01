<?php

declare(strict_types=1);

// A test-only seam (composer.json autoload-dev "files", so it is defined before any test runs):
// PHP serves one request per process, so "another worker reads the cache while this one is
// mid-load" is a probe that runs inside the load. Unqualified calls in Camada\Snapshot resolve
// to Camada\Snapshot\json_decode first; it fires the armed probe once at the snapshot meta's
// decode (the only one with JSON_THROW_ON_ERROR: after the response and its config are read,
// before the container is parsed or written), then defers to the real json_decode.

namespace Camada\Tests {
    final class MidLoad
    {
        public static ?\Closure $probe = null;
    }
}

namespace Camada\Snapshot {
    use Camada\Tests\MidLoad;

    /** @param int<1, max> $depth */
    function json_decode(string $json, ?bool $associative = null, int $depth = 512, int $flags = 0): mixed
    {
        $probe = MidLoad::$probe;
        if ($probe !== null && ($flags & JSON_THROW_ON_ERROR) !== 0) {
            MidLoad::$probe = null;
            $probe();
        }
        return \json_decode($json, $associative, $depth, $flags);
    }
}
