<?php
require __DIR__ . '/composer/vendor/autoload.php';

use Svm\Middleware\Auth;
use Svm\Middleware\Cors;
use Svm\Helpers\Env;
use Svm\Helpers\Response;
use Svm\Helpers\Request;
use Svm\Core\Routes;

Env::InitEnv('./.env');
Cors::InitCors();
// Ensures token is valid if token is expired client must call the refresh token.
//Auth::Token($_SERVER['REMOTE_ADDR']);

// Initialize router
[$router, $method, $path] = Request::initRouter();

// Load routes
Routes::initRoutes($router);

// Resolve request
try {
    $router->resolve($method, $path);
} catch (Throwable $e) {
    Response::error("Unhandled Exception", 500, $e);
}
