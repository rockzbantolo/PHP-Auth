<?php
namespace Mws\Helpers;

use Firebase\JWT\JWT;
use Firebase\JWT\Key;
use Firebase\JWT\ExpiredException;


class Token
{
    private static ?string $jwtSecret = null; // Allow null until set
    private static $expirySeconds = 3600; // 1 Hour

    private static function initSecret(): void
    {
        if (self::$jwtSecret === null) {
            self::$jwtSecret = getenv('JWT_SECRET') ?: 'My-Kiddo-Extreme';
        }
    }

    public static function generateAccessToken($userId, $username): array
    {
        self::initSecret(); // Ensures secret is ready

        $issuedAt  = time();
        $expiresAt = $issuedAt + self::$expirySeconds;

        $payload = [
            'iat'      => $issuedAt,
            'exp'      => $expiresAt,
            'user_id'  => $userId,
            'username' => $username
        ];

        return [
            'token'      => JWT::encode($payload, self::$jwtSecret, 'HS256'),
            'expires_at' => $expiresAt
        ];
    }

    public static function generateRefreshToken($days = 30): array
    {
        $token = bin2hex(random_bytes(32));
        $expiresAt = time() + ($days * 24 * 60 * 60);
        return ['token' => $token, 'expires_at' => $expiresAt];
    }

       /**
     * Decode and validate a JWT
     *
     * @param string $token
     * @return array|null Returns decoded payload as array or null if invalid/expired
     */
    public static function decode(string $token): ?array
    {
        try {
            $decoded = JWT::decode($token, new Key(self::$jwtSecret, 'HS256'));
            return (array) $decoded; // Convert stdClass to array
        } catch (ExpiredException $e) {
            return null; // Token expired
        } catch (\Throwable $e) {
            return null; // Any other invalid token error
        }
    }
}
