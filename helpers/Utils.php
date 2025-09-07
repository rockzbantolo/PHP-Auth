<?php
namespace Mws\Helpers;

use UAParser\Parser;

class Utils {

    public static function getUserId(): ?int
    {
        // Example: if you attach user_id into JWT claims or session
        return $_SESSION['user_id'] ?? null; 
    }

    public static function getClientIp(): string
    {
        $ip = $_SERVER['REMOTE_ADDR'] ?? '0.0.0.0';

        if (!empty($_SERVER['HTTP_X_FORWARDED_FOR'])) {
            $forwardedIps = explode(',', $_SERVER['HTTP_X_FORWARDED_FOR']);
            $ip = trim($forwardedIps[0]);
        }

        return $ip;
    }

    public static function getUserAgent(): string
    {
        return $_SERVER['HTTP_USER_AGENT'] ?? 'unknown';
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

    public static function requireFields(array $data, array $fields): array {
        $errors = [];
        foreach ($fields as $field) {
            if (!isset($data[$field]) || trim($data[$field]) === '') {
                $errors[$field] = "Missing required field: $field";
            }
        }
        return $errors;
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