<?php
namespace Mws\Helpers;

class Utils {

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