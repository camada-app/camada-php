<?php

declare(strict_types=1);

namespace Camada;

/**
 * The SDK's wire identity (SDK-03): x-camada-sdk: <package>/<version>. This literal is the
 * single source: composer.json carries no version field (Packagist reads tags), and the sibling
 * drift guards (camada-backend, camada-web, camada-mkt) parse this file the way they parse a
 * package.json. Plain X.Y.Z only: the analyst's SDK_RE drops anything else.
 */
final class Version
{
    public const VERSION = '0.1.0';
    public const SDK_ID = '@camada/php/' . self::VERSION;
}
