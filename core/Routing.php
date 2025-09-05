<?php
namespace Mws\Core;

use Mws\Helpers\Response;

class Routing
{
    private $router;
    private $prefix;
    private $controller;

    public function __construct($router, string $prefix, string $controller)
    {
        $this->router     = $router;
        $this->prefix     = $prefix;
        $this->controller = $controller;
    }

    public static function map($router, string $prefix, string $controller, callable $callback): void
    {
        $registrar = new self($router, $prefix, $controller);
        $callback($registrar);
    }

    public function get(string $path, string $action, array $middleware = []): self
    {
        return $this->register('GET', $path, $action, $middleware);
    }

    public function post(string $path, string $action, array $middleware = []): self
    {
        return $this->register('POST', $path, $action, $middleware);
    }

    public function put(string $path, string $action, array $middleware = []): self
    {
        return $this->register('PUT', $path, $action, $middleware);
    }

    public function delete(string $path, string $action, array $middleware = []): self
    {
        return $this->register('DELETE', $path, $action, $middleware);
    }

    private function register(string $method, string $path, string $action, array $middleware = []): self
    {
        $allowed = ['GET', 'POST', 'PUT', 'DELETE'];

        if (!in_array($method, $allowed, true)) {
            Response::error(
                "Unsupported HTTP method: $method",
                \Mws\Core\StatusCode::METHOD_NOT_ALLOWED
            );
        }

        if (!method_exists($this->controller, $action)) {
            Response::error(
                "Method '$action' not found in {$this->controller}",
                \Mws\Core\StatusCode::NOT_FOUND
            );
        }

        $this->router->register(
            $method,
            $this->prefix . $path,
            [$this->controller, $action],
            $middleware
        );

        return $this;
    }
}
