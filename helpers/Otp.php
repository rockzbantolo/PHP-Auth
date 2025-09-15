<?php
namespace Svm\Helpers;

use Svm\Core\Base;
use Exception;
use Throwable;
use RuntimeException;

class Otp extends Base
{
    /**
     * Generate a 6-digit OTP and store it in the database with UTC expiry
     */
    public function generateOTP(string $email): int
    {
        try {
            
            $otp = str_pad(rand(0, 999999), 6, '0', STR_PAD_LEFT);
            $expiresAt = date('Y-m-d H:i:s', strtotime('+10 minutes'));

            $stmt = "INSERT INTO user_otps (email, otp, expires_at, is_used) 
                     VALUES (?, ?, ?, 0)
                     ON DUPLICATE KEY UPDATE otp = VALUES(otp), expires_at = VALUES(expires_at), is_used = 0";

            $rowsAffected = $this->insert($stmt, [$email, $otp, $expiresAt]);

            if ($rowsAffected <= 0) {
                throw new Exception('Failed to insert OTP');
            }

            return $otp;

        } catch (Throwable $e) {
            throw new RuntimeException("Failed to generate OTP: " . $e->getMessage(), 0, $e);
        }
    }

    /**
     * Verify OTP against email using UTC time
     */
    public function verifyOTP(string $email, string $otp): bool
    {
        try {
            // Use query() instead of fetchAssociative()
            $stmt = "SELECT * FROM user_otps WHERE email = ? AND otp = ? AND is_used = 0 AND expires_at > UTC_TIMESTAMP() LIMIT 1";

            $result = $this->selectOne($stmt, [$email, $otp]);

            // query() returns an array; empty array means no matching OTP
            if (!empty($result)) {
                // Mark OTP as used
                $updateStmt = "UPDATE user_otps SET is_used = 1 WHERE email = ? AND otp = ?";
                $this->update($updateStmt, [$email, $otp]);

                return true;
            }

            return false;

        } catch (Throwable $e) {
            throw new RuntimeException("Failed to verify OTP: " . $e->getMessage(), 0, $e);
        }
    }

}
