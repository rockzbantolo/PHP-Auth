<?php
namespace Svm\Services;

use Svm\Repository\UserRepo;
use Svm\Core\RespCode;
use Svm\Helpers\Response;
use Svm\Helpers\Utils;
use Svm\Helpers\Token;
use Svm\Helpers\Otp;
use Svm\Helpers\Emailer;

use RuntimeException;
use Throwable;


class AuthSvc
{
    private UserRepo $model;
    private $maxAttempts = 5;
    private $lockDurationMinutes = 15;

    public function __construct()
    {
        $this->model = new UserRepo();
    }

    public function findAllUsers(int $page, int $limit)
    {
        try {

            if (!Utils::validateId($page) || !Utils::validateId($limit)) {
                return Response::error("Invalid page or limit", RespCode::BAD_REQUEST);
            }

            $result = $this->model->findAll((int)$page, (int)$limit);

            return Response::success(
                $result['data'],
                "Users retrieved successfully",
                RespCode::OK,
                $result['pagination']
            );

        } catch (Throwable $e) {
            return Response::error("Failed to fetch users", RespCode::INTERNAL_SERVER_ERROR, $e);
        }
    }

    public function findUserById($id)
    {
        try {

            if (!Utils::validateId($id)) {
                return Response::error("Invalid user ID", RespCode::BAD_REQUEST);
            }

            $user = $this->model->findById($id);
            
            return $user ? 
                Response::success($user, "User found") : 
                Response::notFound("User with ID $id not found");
                
        } catch (Throwable $e) {
            return Response::error("Failed to fetch user", RespCode::INTERNAL_SERVER_ERROR, $e);
        }
    }

    public function createUser(array $payload)
    {
        try {
            
            $data = $this->model->normalize($payload, ['created_by' => 0]);

            // Validate required fields
            if (!Utils::hasRequiredFields($data, ['username', 'password', 'email'])) {
                return Response::error("Credentials are required", RespCode::UNPROCESSABLE_ENTITY);
            }

            // Validate email format
            if (!Utils::validateEmail($data['email'])) {
                return Response::error("Invalid email format", RespCode::BAD_REQUEST);
            }

            // Attempt to create user
            try {
                $this->model->addUser($data);
            } catch (RuntimeException $e) {
                if ($error = $this->model->handleDBError($e)) {
                    return Response::error($error['message'], $error['code']); // <-- use "status" consistently
                }
                throw $e;
            }

            return Response::success([], "User created successfully", RespCode::CREATED);

        } catch (Throwable $e) {
            return Response::error("Failed to register user", RespCode::INTERNAL_SERVER_ERROR, $e);
        }
    }

    public function updateUserById(int $id, array $payload)
    {
        try {

            if (!Utils::validateId($id)) {
                return Response::error("Invalid user ID", RespCode::BAD_REQUEST);
            }

            // Get actor
            $data = $this->model->normalize($payload, ['updated_by' => 0]);

            if (!empty($data['email']) && !Utils::validateEmail($data['email'])) {
                return Response::error("Invalid email format", RespCode::BAD_REQUEST);
            }

            try {
                
                if(!$this->model->updateUser($id, $data)) {
                    return Response::error("User not found or no changes applied", RespCode::NOT_FOUND);;
                }

            } catch (RuntimeException $e) {
                if ($error = $this->model->handleDBError($e)) {
                    return Response::error($error['message'], $error['code']);
                }
                throw $e;
            }

            return Response::success([], "User updated successfully");

        } catch (Throwable $e) {
            return Response::error("Failed to update user an error occured", RespCode::INTERNAL_SERVER_ERROR, $e);
        }
    }

    public function deleteUserById($id)
    {
        try {

            if (!Utils::validateId($id)) {
                return Response::error("Invalid user ID", RespCode::BAD_REQUEST);
            }

            $result = $this->model->deleteUser($id);
            return $result ? 
                    Response::success([], "User soft-deleted successfully") : 
                    Response::error("User deletion failed or user not found", RespCode::NOT_FOUND);

        } catch (Throwable $e) {
            return Response::error("Failed to delete user", RespCode::INTERNAL_SERVER_ERROR, $e);
        }
    }

    public function undeleteUserById($id)
    {
        try {

            if (!Utils::validateId($id)) {
                return Response::error("Invalid user ID", RespCode::BAD_REQUEST);
            }

            $result = $this->model->undeleteUser($id);
            return $result ? 
                    Response::success([], "User undeleted successfully") : 
                    Response::error("User undeletion failed or user not found", RespCode::NOT_FOUND);

        } catch (Throwable $e) {
            return Response::error("Failed to delete user", RespCode::INTERNAL_SERVER_ERROR, $e);
        }
    }

    public function loginUser($data): array
    {
        try {
            // Validation
            if(!Utils::hasRequiredFields($data, ['username', 'password'])){
                return Response::error("Username and Password is Required", RespCode::UNPROCESSABLE_ENTITY);
            }

            // Get user
            $user = $this->model->findByUsername($data['username']);
            if ($user === null || !password_verify($data['password'], $user['password_hash'])) {
                return $this->handleInvalidCredentials($user);
            }

            // Check account status
            if (!empty($user['deleted_at'])) {
                return Response::error("Your account has been deleted. Contact system admin", RespCode::FORBIDDEN);
            }
            if (!$user['is_approved']) {
                return Response::error("Your account is not approved yet. Contact system admin", RespCode::FORBIDDEN);
            }
            if ($user['is_online']) {
                return Response::error("User already logged in on another device", RespCode::FORBIDDEN);
            }

            // Checkpoint
            if (!empty($user['lock_until']) && strtotime($user['lock_until']) > time()) {
                $formattedRemaining = Utils::formatRemainingLockTime($user['lock_until']);
                return Response::error(
                    "Account locked. Try again in $formattedRemaining (mm:ss)",
                    RespCode::FORBIDDEN,
                    null,
                    ['remaining_attempts' => 0]
                );
            }
            if ($user['failed_attempts'] > 0 || !empty($user['lock_until'])) {
                $this->model->resetLoginAttempts($user['user_id']);
            }

            // Generate and store tokens
            $access  = Token::generateAccessToken($user['user_id'], $user['username']);
            $refresh = Token::generateRefreshToken();

            if(!$this->model->storeTokens($user['user_id'], $access['token'], $refresh['token'], $access['expires_at'], $refresh['expires_at'])) {
                 Response::error("Login failed to stored token", RespCode::INTERNAL_SERVER_ERROR);
            }

            return Response::success(
                    ['user_id' => $user['user_id'],
                    'username' => $user['username'],
                    'access_token' => $access['token'],
                    'refresh_token' => $refresh['token'],
                    'expires_in' => $access['expires_at'],
                    'refresh_expires_in' => $refresh['expires_at'] - time()],
                    "Welcome {$user['username']}");
            
        } catch (Throwable $e) {
            return Response::error("Failed to process login: " .$e->getMessage(), RespCode::INTERNAL_SERVER_ERROR, $e);
        }
    }

    public function logoutUser($data)
    {
        try {
            
            if (!Utils::validateId($data['user_id'])) {
                return Response::error("Invalid user ID", RespCode::BAD_REQUEST);
            }

            return $this->model->clearTokens($data['user_id']) ? 
                    Response::success([], "Logout successful") : 
                    Response::error("User already logged out or no record found", RespCode::NOT_FOUND);
             
        } catch (Throwable $e) {
            return Response::error("Failed to logout", RespCode::INTERNAL_SERVER_ERROR, $e);
        }
    }

    public function refreshUserToken($data)
    {
        try {

            if (!Utils::hasRequiredFields($data, ['refresh_token'])) {
                  Response::error("Refresh Token is required", RespCode::BAD_REQUEST);
            }

            $tokenData = $this->model->findRefreshToken($data['refresh_token']);

            if (!$tokenData || strtotime($tokenData['refresh_expiry']) < time()) {
                return Response::error("Invalid or expired refresh token", RespCode::UNAUTHORIZED);
            }

            $access  = Token::generateAccessToken($tokenData['user_id'], $tokenData['username']);
            $refresh = Token::generateRefreshToken();

            $success = $this->model->updateAccessToken(
                $tokenData['user_id'],
                $access['token'],
                $access['expires_at'],
                $refresh['token'],
                $refresh['expires_at']
            );

            return $success ? 
            Response::success([
                'jwt' => $access['token'],
                'expires_at' => $access['expires_at'],
                'refresh_token' => $refresh['token'],
                'refresh_expires_at' => $refresh['expires_at']],
                "Token refreshed successfully") : 

            Response::error("Token refresh failed", RespCode::INTERNAL_SERVER_ERROR);

        } catch (Throwable $e) {
            return Response::error("Failed to refresh token", RespCode::INTERNAL_SERVER_ERROR, $e);
        }
    }

    public function requestUserOTP($data)
    {
        try {
                    
            $email = $data['email'];
            
            if (!Utils::hasRequiredFields($data, ['email'])) {
                  Response::error("Email is required", RespCode::BAD_REQUEST);
            }

            // Fetch user data from your model
            $user = $this->model->findByEmail($email);
            
            if (!$user) {
                Response::error("User not found", RespCode::NOT_FOUND);
            }

            // Check if 2FA is enabled
            if (!$user['is_two_factor']) {
                Response::error("Two-Factor Authentication is not enabled for this user", RespCode::FORBIDDEN);
            }

            // Generate OTP and send email
            $otpHelper = new Otp;
            $otp = $otpHelper->generateOTP($email);

            return Emailer::sendOTP($email, $otp) ?
                    Response::success(['email' => $email], "OTP has been sent successfully") : 
                    Response::error("Request Otp failed", RespCode::INTERNAL_SERVER_ERROR);

            } catch (Throwable $e) {
                Response::error("Failed to send OTP", RespCode::INTERNAL_SERVER_ERROR, $e);
            }
    }

    public function verifyUserOTP($data)
    {
        try {
            // Validate required fields
            if (!Utils::hasRequiredFields($data, ['email', 'otp'])) {
                return Response::error("Email and OTP are required", RespCode::BAD_REQUEST);
            }

            $email = $data['email'];
            $otp   = $data['otp'];

            $otpHelper = new Otp;

            return $otpHelper->verifyOTP($email, $otp) ? 
                    Response::success(['email' => $email], "OTP verified successfully") : 
                    Response::error("Invalid or expired OTP", RespCode::UNAUTHORIZED);

        } catch (Throwable $e) {
            return Response::error("Failed to verify OTP", RespCode::INTERNAL_SERVER_ERROR, $e);
        }
    }

    public function getUserActivity($userId)
    {  
        $page = $_GET['page'] ?? 1;
        $limit = $_GET['limit'] ?? 50;

        try {

            if (!Utils::validateId($userId)) {
                return Response::error("Invalid user ID", RespCode::BAD_REQUEST);
            }

            if (!Utils::validateId($page) || !Utils::validateId($limit)) {
                return Response::error("Invalid page or limit", RespCode::BAD_REQUEST);
            }

            $result = $this->model->findUserActivity($userId, $limit, $page);

            return Response::success(
                $result['data'],
                "User activity retrieved successfully",
                RespCode::OK,
                $result['pagination']
            );

        } catch (Throwable $e) {
            return Response::error("Failed to fetch user activity", RespCode::INTERNAL_SERVER_ERROR, $e);
        }
    }

    /**
     * Handle invalid credentials (user not found or wrong password).
     */
    private function handleInvalidCredentials(?array $user): array
    {
        $userId = $user['user_id'] ?? null;
        $failedAttempts = ($user['failed_attempts'] ?? 0) + 1;
        $lockUntil = $failedAttempts >= $this->maxAttempts
            ? date('Y-m-d H:i:s', strtotime("+{$this->lockDurationMinutes} minutes"))
            : null;

        if ($userId) {
            $this->model->updateLoginAttempts($userId, $failedAttempts, $lockUntil);
        }

        $remainingAttempts = Utils::remainingAttempts($failedAttempts, $this->maxAttempts);
        $message = $lockUntil
            ? "Account locked. Try again later: " . date('H:i', strtotime($lockUntil))
            : "Invalid credentials. $remainingAttempts attempts remaining";

        return Response::error(
            $message,
            $lockUntil ? RespCode::FORBIDDEN : RespCode::UNAUTHORIZED,
            null,
            ['remaining_attempts' => $remainingAttempts]
        );
    }
}
