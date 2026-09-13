<?php

// The fixture app SapiTest drives over php -S: a plain front controller, exactly the shape the
// example app has — Sapi::run() first, then the app's own routing on $_SERVER.
declare(strict_types=1);

require __DIR__ . '/../../vendor/autoload.php';

use Camada\Camada;
use Camada\Http\Sapi;

$cam = Camada::default();
$ctx = Sapi::run($cam);
if ($ctx === null) {
    return;
}
$path = parse_url($_SERVER['REQUEST_URI'] ?? '/', PHP_URL_PATH);
switch ($path) {
    case '/':
        echo 'hello ' . ($ctx->rid ?? '-');
        break;
    case '/tag':
        echo $cam->scriptTag($ctx);
        break;
    case '/status':
        http_response_code(201);
        header('x-app: 1');
        echo 'made';
        break;
    case '/track':
        $cam->track($ctx, 'login_failed', 'alice@example.com');
        http_response_code(401);
        echo 'nope';
        break;
    case '/gate':
        $answer = $cam->serveChallenge($ctx);
        if ($answer !== null) {
            Sapi::send($answer);
            return;
        }
        echo 'secret page';
        break;
    case '/api':
        header('content-type: application/json');
        echo '{"ok":true}';
        break;
    case '/echo':
        echo (string) file_get_contents('php://input');
        break;
    case '/crash':
        throw new RuntimeException('app bug');
    default:
        http_response_code(404);
        echo 'nothing here';
}
