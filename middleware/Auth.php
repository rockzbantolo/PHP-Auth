<?php
namespace Svm\Middleware;

use Svm\Helpers\Response;
use Svm\Core\RespCode;
use Svm\Helpers\Token;
use Svm\Core\Connection;
use Doctrine\DBAL\ParameterType;

use DateTime;
use Throwable;

class Auth
{
    private static string $validUser = 'Rockz';
    private static string $validPass = '122190';
    private static string $validApiKey = '1234567890abcdef';

    // Rate Limit
    private static int $limit = 300;        // Max requests
    private static int $windowSeconds = 60; // Per minute


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
        self::rateLimit($userId, $ip);

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

    /**
     * Enforces rate limiting based on user ID and IP address.
     *
     * @param int|null $userId User ID (nullable)
     * @param string $ip IP address
     */
    private static function rateLimit(?int $userId, string $ip): void
    {
        $conn = Connection::getInstance();

        $windowSeconds = self::$windowSeconds ?? 60; // Default to 60 seconds
        $limit = self::$limit ?? 100; // Default to 100 requests

        $windowStart = (new DateTime())->setTimestamp(
            floor(time() / $windowSeconds) * $windowSeconds
        )->format('Y-m-d H:i:s');

        // Try fetch current request count
        $sqlSelect = 'SELECT request_count
                      FROM rate_limits
                      WHERE user_id IS ? AND ip_address = ? AND window_start = ?';

        try {
            $result = $conn->executeQuery(
                $sqlSelect,
                [$userId, $ip, $windowStart],
                [
                    $userId === null ? ParameterType::NULL : ParameterType::INTEGER,
                    ParameterType::STRING,
                    ParameterType::STRING
                ]
            )->fetchAssociative();

            if ($result && $result['request_count'] >= $limit) {
                Response::error('Rate limit exceeded. Try again later.', RespCode::TOO_MANY_REQUESTS)->send();
                exit;
            }

            if ($result) {
                $sqlUpdate = 'UPDATE rate_limits
                              SET request_count = request_count + 1
                              WHERE user_id IS ? AND ip_address = ? AND window_start = ?';
                $conn->executeStatement(
                    $sqlUpdate,
                    [$userId, $ip, $windowStart],
                    [
                        $userId === null ? ParameterType::NULL : ParameterType::INTEGER,
                        ParameterType::STRING,
                        ParameterType::STRING
                    ]
                );
            } else {
                $sqlInsert = 'INSERT INTO rate_limits (user_id, ip_address, request_count, window_start)
                              VALUES (?, ?, 1, ?)';
                $conn->executeStatement(
                    $sqlInsert,
                    [$userId, $ip, $windowStart],
                    [
                        $userId === null ? ParameterType::NULL : ParameterType::INTEGER,
                        ParameterType::STRING,
                        ParameterType::STRING
                    ]
                );
            }
        } catch (Throwable $e) {
            Response::error('Database error: ' . $e->getMessage(), RespCode::INTERNAL_SERVER_ERROR)->send();
            exit;
        }
    }
}
