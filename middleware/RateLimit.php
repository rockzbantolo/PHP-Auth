<?php
namespace Svm\Middleware;

use Svm\Core\Base;
use Svm\Helpers\Response;
use Svm\Core\RespCode;
use Doctrine\DBAL\ParameterType;
use DateTime;

class RateLimit extends Base
{
    //private static $windowSeconds = 60; // Default window (1 minute)
    //private static $limit = 100; // Default max requests

    /**
     * Enforce rate limiting based on user ID or IP address.
     *
     * @param ?int $userId User ID (nullable for guest users)
     * @param string $ip Client IP address
     * @throws RuntimeException on database errors
     */
    public static function enabled(int $userId, string $ip)
    {
        self::rateLimit($userId, $ip, 60, 100);
    }

    private static function rateLimit(?int $userId, string $ip, ?int $windowSeconds = null, ?int $limit = null): void
    {
        $windowStart = (new DateTime())->setTimestamp(
            floor(time() / $windowSeconds) * $windowSeconds
        )->format('Y-m-d H:i:s');

        $params = [$userId, $ip, $windowStart];
        $types  = [$userId === null ? ParameterType::NULL : ParameterType::INTEGER,
            ParameterType::STRING,
            ParameterType::STRING
        ];

        // Check current request count
        $result = self::selectOne(
            'SELECT request_count FROM rate_limits WHERE user_id IS ? AND ip_address = ? AND window_start = ?',
            $params,
            $types
        );

        if ($result && $result['request_count'] >= $limit) {
            Response::error('Rate limit exceeded. Try again later.', RespCode::TOO_MANY_REQUESTS)->send();
            exit;
        }

        // Update or insert
        if ($result) {
            self::update(
                'UPDATE rate_limits SET request_count = request_count + 1 WHERE user_id IS ? AND ip_address = ? AND window_start = ?',
                $params,
                $types
            );
        } else {
            self::insert(
                'INSERT INTO rate_limits (user_id, ip_address, request_count, window_start) VALUES (?, ?, 1, ?)',
                $params,
                $types
            );
        }
    }

}