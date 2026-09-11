<?php

declare(strict_types=1);

namespace Camada\Transport;

/**
 * The one HTTP seam. The engine, the snapshot client and the event spool speak to the analyst
 * through a transport, so tests inject an in-process fake and production uses the stream
 * wrapper. A transport never throws: a network failure is a status-0 response, which every
 * caller treats as "keep what we have".
 */
interface TransportInterface
{
    public function send(HttpRequest $req): HttpResponse;
}
