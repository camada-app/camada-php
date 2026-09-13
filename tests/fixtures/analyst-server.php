<?php

// A router for php -S standing in for the analyst behind a real SAPI test: GET /snapshot
// answers 204 after ANALYST_DELAY_MS (nothing published — enough to prove the refresh ran
// after the response), POST /e appends each batch to ANALYST_SINK.
declare(strict_types=1);

$path = parse_url($_SERVER['REQUEST_URI'] ?? '/', PHP_URL_PATH);
if ($path === '/snapshot') {
    usleep(1000 * (int) (getenv('ANALYST_DELAY_MS') ?: '0'));
    header('x-camada-config: {"beacon":true,"trusted_proxy":{"mode":"none"}}');
    http_response_code(204);
    return;
}
if ($path === '/e' && ($_SERVER['REQUEST_METHOD'] ?? '') === 'POST') {
    $sink = getenv('ANALYST_SINK');
    if (is_string($sink) && $sink !== '') {
        file_put_contents($sink, (string) file_get_contents('php://input') . "\n", FILE_APPEND);
    }
    http_response_code(202);
    return;
}
http_response_code(404);
