<?php
namespace Mws\Middleware;

use Mws\Helpers\Response;
use Mws\Core\StatusCode;
use Mws\Helpers\Token;
use Mws\Core\Connection;


class Auth
{
    private static string $validUser = 'Rockz';
    private static string $validPass = '122190';
    private static string $validApiKey = '1234567890abcdef';

    public static function BasicAuth(): void
    {
        // For Apache fallback if PHP_AUTH_USER is not set
        if (!isset($_SERVER['PHP_AUTH_USER'])) {
            if (isset($_SERVER['HTTP_AUTHORIZATION'])) {
                if (preg_match('/Basic\s+(.*)$/i', $_SERVER['HTTP_AUTHORIZATION'], $matches)) {
                    [$user, $pass] = explode(':', base64_decode($matches[1]), 2);
                    $_SERVER['PHP_AUTH_USER'] = $user;
                    $_SERVER['PHP_AUTH_PW'] = $pass;
                }
            }
        }

        // Auth check
        if (
            !isset($_SERVER['PHP_AUTH_USER'], $_SERVER['PHP_AUTH_PW']) ||
            $_SERVER['PHP_AUTH_USER'] !== self::$validUser ||
            $_SERVER['PHP_AUTH_PW'] !== self::$validPass
        ) {
            header('WWW-Authenticate: Basic realm="MWS API"');
            Response::error("Authentication failed", 401);
            exit; // Make sure script stops after failed auth
        }
    }

    // API Key Authentication
    public static function ApiKey(): void
    {
        $headers = getallheaders();
        $apiKey = $headers['MWS-API-KEY'] ?? null;

        if ($apiKey !== self::$validApiKey) {
            Response::error("Invalid API Key", 401);
            exit;
        }
    }

    // JWT Authentication
    public static function JWToken(): array
    {
        $headers = getallheaders();
        $authHeader = $headers['Authorization'] ?? '';

        if (!$authHeader || !preg_match('/Bearer\s(\S+)/', $authHeader, $matches)) {
            Response::error("Missing or invalid Authorization header", StatusCode::UNAUTHORIZED)->send();
            exit;
        }

        $jwt = $matches[1];

        // Decode & validate signature
        $payload = Token::decode($jwt);
        if (!$payload) {
            Response::error("Invalid or expired token", StatusCode::UNAUTHORIZED)->send();
            exit;
        }

        // Open DB connection via your Connection class
        $conn = Connection::getInstance();

        $stmt = $conn->prepare("
            SELECT *
            FROM user_tokens
            WHERE jwt_token = ?
              AND token_expiry > NOW()
            LIMIT 1
        ");

        $stmt->bind_param("s", $jwt);
        $stmt->execute();
        $result = $stmt->get_result()->fetch_assoc();

        if (!$result) {
            Response::error("Token not found or expired", StatusCode::UNAUTHORIZED)->send();
            exit;
        }

        // Optionally release connection if you're caching
        Connection::release($conn);

        return [
            'jwt'    => $payload,   // decoded JWT
            'record' => $result     // DB row
        ];
    }

}
