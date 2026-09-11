<?php

// A router for php -S standing in for the analyst over real HTTP: GET /snapshot answers a
// gzipped frame with an etag, POST /e echoes the batch size, anything else is 404.
declare(strict_types=1);

$path = parse_url($_SERVER['REQUEST_URI'] ?? '/', PHP_URL_PATH);
if ($path === '/snapshot') {
    $meta = json_encode(['version' => 'z']);
    $payload = pack('V', strlen($meta)) . $meta . 'BLK';
    $gz = str_contains($_SERVER['HTTP_ACCEPT_ENCODING'] ?? '', 'gzip');
    header('etag: "z"');
    header('x-camada-config: {"beacon":true}');
    if ($gz) {
        header('content-encoding: gzip');
        echo gzencode($payload);
    } else {
        echo $payload;
    }
    return;
}
if ($path === '/e' && ($_SERVER['REQUEST_METHOD'] ?? '') === 'POST') {
    $rows = json_decode((string) file_get_contents('php://input'), true);
    http_response_code(202);
    header('content-type: application/json');
    echo json_encode(['n' => is_array($rows) ? count($rows) : -1, 'tenant' => $_SERVER['HTTP_X_TENANT'] ?? null]);
    return;
}
http_response_code(404);
echo 'nope';
