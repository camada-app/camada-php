<?php

declare(strict_types=1);

namespace Camada;

final class Constants
{
    /**
     * Tap identifier this SDK claims on the wire. The server validates against its own enum and
     * derives the capability mask itself (edge-analyst src/capabilities.js): an SDK can never grant
     * itself capability bits, only name its position — and an unknown name is silently read as a
     * proxy, so this literal is load-bearing.
     */
    public const TAP = 'sdk-php';

    public const DEFAULT_REFRESH_S = 30.0;
    /** 5 carries the tenant's ordered custom rules (§D3); a tenant without one is answered with the next container down. */
    public const DEFAULT_SNAPSHOT_VERSION = 5;
    public const KILL_SWITCH_ENV = 'CAMADA_DISABLED';

    public const SCRIPT_PATH = '/_cam/b.js';
    public const FP_PATH = '/_cam/fp';
    public const FP_MAX = 32 * 1024;               // matches the server's /fp cap: never accept what ingest will 413
    public const CHALLENGE_PATH = '/__camada/challenge';
    public const BODY_MAX = 4 * 1024;              // the verify form is ~120 bytes; anything larger is not ours

    public const SESSION_COOKIE = '_sfp';          // same cookie as the edge collector: sid/ns comparable across taps
    public const SESSION_MAX_AGE = 2592000;        // 30 days
}
