<?php
namespace Svm\Helpers;

use PHPMailer\PHPMailer\PHPMailer;
use Exception;

class Emailer {

    /**
     * Initialize PHPMailer with SMTP settings
     * Automatically switches to test credentials if USE_TEST_EMAIL=true
     */
    private static function initMailer(): PHPMailer {
        
        $useTest = getenv('USE_TEST_EMAIL') === 'true';

        $mail = new PHPMailer(true);
        $mail->isSMTP();
        $mail->SMTPKeepAlive = getenv('SMTP_KEEP_ALIVE');

        // Select SMTP credentials
        $mail->Host       = $useTest ? getenv('SMTP_TEST_HOST') : getenv('SMTP_HOST');
        $mail->SMTPAuth   = getenv('SMTP_AUTH');
        $mail->Username   = $useTest ? getenv('SMTP_TEST_USERNAME') : getenv('SMTP_USERNAME');
        $mail->Password   = $useTest ? getenv('SMTP_TEST_PASSWORD') : getenv('SMTP_PASSWORD');
        $mail->SMTPSecure = getenv('SMTP_SECURE') ?: 'ssl';
        $mail->Port       = $useTest ? getenv('SMTP_TEST_PORT') : getenv('SMTP_PORT');

        $mail->setFrom($mail->Username, 'Service Management');
        $mail->isHTML(true);

        return $mail;
    }

    /**
     * Send OTP email
     */
    public static function sendOTP(string $toEmail, string $otp): bool {
        try {
            $mail = self::initMailer();
            $mail->addAddress($toEmail);

            $mail->Subject = 'Your OTP Code';
            $mail->Body = "
                <div style='font-family: Arial, sans-serif; padding: 20px;'>
                    <h2 style='color: #333; margin-bottom: 10px;'>Your OTP Code</h2>
                    <p style='margin: 0 0 15px;'>Please use the following one-time password to continue. 
                    It will expire in 10 minutes.</p>
                    <div style='margin: 20px 0; padding: 15px; border: 1px solid #ddd; 
                                background-color: #f9f9f9; text-align: center; 
                                font-size: 22px; font-weight: bold; letter-spacing: 4px;'>
                        $otp
                    </div>
                    <p style='margin: 0 0 10px;'>If you did not request this code, you can safely ignore this email.</p>
                    <p style='font-size: 12px; color: #888; margin-top: 30px;'>Service Management System</p>
                </div>
            ";
            $mail->AltBody = "Your OTP code is $otp. It is valid for 10 minutes.";

            $mail->send();
            return true;

        } catch (Exception $e) {
            throw new Exception("Email sending failed: " . $e->getMessage(), 0, $e);
        }

    }
}
