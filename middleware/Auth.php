<?php
namespace Svm\Middleware;

use Svm\Helpers\Response;
use Svm\Core\RespCode;
use Svm\Helpers\Token;
use Svm\Core\Connection;
use Svm\Middleware\RateLimit;
use Doctrine\DBAL\ParameterType;


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

    public static function Token(string $ip): array
    {
        $auth = self::JWToken(); 
        $userId = $auth['jwt']['user_id'] ?? null;
        RateLimit::enabled($userId, $ip);

        return $auth;
    }

    /**
     * Validates JWT and retrieves associated user token data.
     *
     * @return array{ jwt: array, record: array|null } Decoded JWT payload and database record
     */
    private static function JWToken(): array
    {
        $headers = getallheaders();
        $authHeader = $headers['Authorization'] ?? '';

        if (!$authHeader || !preg_match('/Bearer\s(\S+)/', $authHeader, $matches)) {
            Response::error('Missing or invalid Authorization header', RespCode::UNAUTHORIZED)->send();
            exit;
        }

        $jwt = $matches[1];

        // Decode & validate signature
        $payload = Token::decode($jwt);
        if (!$payload) {
            Response::error('Invalid or expired token', RespCode::UNAUTHORIZED)->send();
            exit;
        }

        // Get DB connection
        $conn = Connection::getInstance();

        // Prepare query
        $sql = 'SELECT *
                FROM user_tokens
                WHERE jwt_token = ?
                AND token_expiry > NOW()
                LIMIT 1';

        try {
            $result = $conn->executeQuery($sql, [$jwt], [ParameterType::STRING])->fetchAssociative();

            if (!$result) {
                Response::error('Token not found or expired', RespCode::UNAUTHORIZED)->send();
                exit;
            }

            return [
                'jwt' => $payload,
                'record' => $result
            ];
        } catch (\Exception $e) {
            Response::error('Database error: ' . $e->getMessage(), RespCode::INTERNAL_SERVER_ERROR)->send();
            exit;
        }
    }
}
