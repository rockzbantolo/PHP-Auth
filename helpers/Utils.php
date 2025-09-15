<?php
namespace Svm\Helpers;

use UAParser\Parser;

class Utils {

    public static function getUserId(): ?int
    {
        // Example: if you attach user_id into JWT claims or session
        return $_SESSION['user_id'] ?? null; 
    }

    public static function getClientIp(): string
    {
        $ip = $_SERVER['HTTP_X_FORWARDED_FOR'] ?? $_SERVER['REMOTE_ADDR'] ?? null;
        $ip = $ip ? trim(explode(',', $ip)[0]) : null;
        return filter_var($ip, FILTER_VALIDATE_IP) ? $ip : '0.0.0.0';
    }

    public static function getUserAgent(): string
    {
        return $_SERVER['HTTP_USER_AGENT'] ?? 'Unknown';
    }

    public static function getDeviceInfo(): string
    {
        $ua = self::getUserAgent();
        $parser = Parser::create();
        $result = $parser->parse($ua);

        $info = [
            //'raw'      => $ua,
            'browser'  => $result->ua->family ?? 'Unknown',
            'platform' => $result->os->family ?? 'Other',
            'device'   => $result->device->family ?? 'Unknown',
        ];

        return json_encode($info, JSON_UNESCAPED_SLASHES);
    }

    public static function hasRequiredFields(array $data, array $fields): bool {
        foreach ($fields as $field) {
            if (!isset($data[$field]) || trim($data[$field]) === '') {
                return false;
            }
        }
        return true;
    }

    public static function validateEmail(string $email): bool {
        return filter_var($email, FILTER_VALIDATE_EMAIL) !== false;
    }

    public static function validateId($id): bool {
        return is_numeric($id) && $id > 0;
    }

    public static function hashPassword(string $password): string {
        return password_hash($password, PASSWORD_BCRYPT);
    }

    public static function formatRemainingLockTime(string $lockUntil): string {
        $remaining = strtotime($lockUntil) - time();
        $minutes = floor($remaining / 60);
        $seconds = $remaining % 60;
        return sprintf("%02d:%02d", $minutes, $seconds);
    }

    public static function formatRemaining(int $expiryTimestamp, bool $includeDays = false): string {
        $remaining = max(0, $expiryTimestamp - time());

        if (!$includeDays) {
            return gmdate('H:i:s', $remaining);
        }

        $days    = floor($remaining / 86400);
        $hours   = floor(($remaining % 86400) / 3600);
        $minutes = floor(($remaining % 3600) / 60);
        $seconds = $remaining % 60;

        return sprintf("%02d:%02d:%02d:%02d", $days, $hours, $minutes, $seconds);
    }

    public static function remainingAttempts(int $failed, int $max): int {
        return max(0, $max - $failed);
    }
    
}