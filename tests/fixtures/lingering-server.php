<?php

// A raw-socket stand-in for a dev server that keeps the connection open after the response is
// complete (wrangler dev answers chunked and idle-closes seconds later). Run as `php lingering-server.php
// <port>`: GET /chunked answers a chunked body with its terminating chunk, GET /length a
// Content-Length body, and then holds the socket open for three seconds before closing it.
declare(strict_types=1);

$port = (int) ($argv[1] ?? 0);
$server = stream_socket_server("tcp://127.0.0.1:{$port}", $errno, $errstr);
if ($server === false) {
    fwrite(STDERR, "listen failed: {$errstr}\n");
    exit(1);
}
echo "started\n";
flush();
/** @var list<array{resource, float}> $open the answered connections and when to close them */
$open = [];
while (true) {
    foreach ($open as $i => [$c, $at]) {
        if (microtime(true) >= $at) {
            fclose($c);
            unset($open[$i]);
        }
    }
    $conn = @stream_socket_accept($server, 0.05);
    if ($conn === false) {
        continue;
    }
    $raw = '';
    while (!str_contains($raw, "\r\n\r\n")) {
        $chunk = fread($conn, 8192);
        if ($chunk === false || $chunk === '') {
            break;
        }
        $raw .= $chunk;
    }
    preg_match('~^\S+ (\S+) HTTP~', $raw, $m);
    $path = $m[1] ?? '/';
    $body = json_encode(['path' => $path, 'keepalive' => true]);
    if ($path === '/chunked') {
        $head = "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nTransfer-Encoding: chunked\r\nConnection: keep-alive\r\n\r\n";
        $half = intdiv(strlen($body), 2);
        $chunks = [substr($body, 0, $half), substr($body, $half)];
        $wire = '';
        foreach ($chunks as $c) {
            $wire .= dechex(strlen($c)) . "\r\n" . $c . "\r\n";
        }
        fwrite($conn, $head . $wire . "0\r\n\r\n");
    } else {
        $head = "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: " . strlen($body) . "\r\nConnection: keep-alive\r\n\r\n";
        fwrite($conn, $head . $body);
    }
    fflush($conn);
    $open[] = [$conn, microtime(true) + 3];   // the idle close a keep-alive server eventually does
}
