<?php
namespace Mws\Controllers;

use Mws\Models\Users;
use Mws\Helpers\Response;
use Mws\Helpers\Utils;
use Mws\Helpers\Token;
use Mws\Core\StatusCode;
use InvalidArgumentException;
use Throwable;
use Exception;


class AuthController
{
    private Users $model;
    private $maxAttempts = 5;
    private $lockDurationMinutes = 15;

    public function __construct()
    {
        $this->model = new Users();
    }

    public function getAllUsers()
    {
        try {
            $page = $_GET['page'] ?? 1;
            $limit = $_GET['limit'] ?? 10;

            if (!Utils::validateId($page) || !Utils::validateId($limit)) {
                return Response::error("Invalid page or limit", StatusCode::BAD_REQUEST);
            }

            $result = $this->model->findAllUsers((int)$page, (int)$limit);

            return Response::success(
                $result['data'],
                "Users retrieved successfully",
                StatusCode::OK,
                $result['pagination']
            );
        } catch (Throwable $e) {
            return Response::error("Failed to fetch users", StatusCode::INTERNAL_SERVER_ERROR, $e->getMessage());
        }
    }

    public function getUserById($id)
    {
        try {
            if (!Utils::validateId($id)) {
                return Response::error("Invalid user ID", StatusCode::BAD_REQUEST);
            }

            $user = $this->model->findUserById($id);
            return $user
                ? Response::success($user, "User found")
                : Response::notFound("User with ID $id not found");
                
        } catch (Throwable $e) {
            return Response::error("Failed to fetch user", StatusCode::INTERNAL_SERVER_ERROR, $e->getMessage());
        }
    }

    public function registerUser($data)
    {
        try {
            
            $errors = Utils::requireFields($data, ['username', 'password', 'email']);
            if (!empty($errors)) {
                return Response::validationError($errors, "Validation failed", StatusCode::UNPROCESSABLE_ENTITY);
            }

            if (!Utils::validateEmail($data['email'])) {
                return Response::error("Invalid email format", StatusCode::BAD_REQUEST);
            }

            // can combine username and email for 1 checking only
            if ($this->model->findByUsername($data['username'])) {
                return Response::error("Username already taken", StatusCode::CONFLICT);
            }

            if ($this->model->findByEmail($data['email'])) {
                return Response::error("Email already taken", StatusCode::CONFLICT);
            }

            $data['password_hash'] = Utils::hashPassword($data['password']);
            unset($data['password']);

            $result = $this->model->createUser($data);

            return $result['success']
                ? Response::success(['id' => $result['id']], "User created successfully", StatusCode::CREATED)
                : Response::error("User creation failed", StatusCode::INTERNAL_SERVER_ERROR);
                
        } catch (Throwable $e) {
            return Response::error("Failed to create user", StatusCode::INTERNAL_SERVER_ERROR, $e->getMessage());
        }
    }

    public function updateUserById($id, $data)
    {
        try {

            if (!Utils::validateId($id)) {
                return Response::error("Invalid user ID", StatusCode::BAD_REQUEST);
            }

            if (isset($data['username'])) {
                $user = $this->model->findByUsername($data['username']);
                if ($user && (int)$user['user_id'] !== (int)$id) {
                    return Response::error("Username is not available", StatusCode::CONFLICT);
                }
            }

            if (isset($data['email']) && !Utils::validateEmail($data['email'])) {
                return Response::error("Invalid email format", StatusCode::BAD_REQUEST);
            }

            if (isset($data['password'])) {
                $data['password_hash'] = Utils::hashPassword($data['password']);
                unset($data['password']);
            }

            $result = $this->model->updateUser($id, $data);
            return $result
                ? Response::success([], "User updated successfully")
                : Response::error("User update failed or user not found", StatusCode::NOT_FOUND);

        } catch (Throwable $e) {
            return Response::error("Failed to update user", StatusCode::INTERNAL_SERVER_ERROR, $e->getMessage());
        }
    }

    public function deleteUserById($id)
    {
        try {

            if (!Utils::validateId($id)) {
                return Response::error("Invalid user ID", StatusCode::BAD_REQUEST);
            }

            $result = $this->model->deleteUser($id);
            return $result['success']
                ? Response::success([], "User soft-deleted successfully")
                : Response::error("User deletion failed or user not found", StatusCode::NOT_FOUND);

        } catch (Throwable $e) {
            return Response::error("Failed to delete user", StatusCode::INTERNAL_SERVER_ERROR, $e->getMessage());
        }
    }

    public function login($data)
    {
        try {
            // VALIDATION
            $errors = Utils::requireFields($data, ['username', 'password']);
            if (!empty($errors)) {
                return Response::validationError($errors, "Validation failed", StatusCode::UNPROCESSABLE_ENTITY);
            }

            // GET DETAILS
            $user = $this->model->findByUsername($data['username']);
            if (!$user) {
                return Response::error("Invalid credentials", StatusCode::UNAUTHORIZED);
            }

            // CHECK REMOVAL
            if ($user['deleted_at'] !== null) {
                return Response::error("Your account has been removed. Please contact the administrator.", StatusCode::FORBIDDEN);
            }

            // CHECK APPROVAL
            if ($user['is_approved'] == 0) {
                return Response::error("Your account is not approved yet.", StatusCode::FORBIDDEN);
            }

            // CHECK STATUS
            if ($user['is_online'] == 1) {
                return Response::error("User already logged in on another device", StatusCode::FORBIDDEN);
            }

            // CHECK ACCOUNT LOCK
            if (!empty($user['lock_until']) && strtotime($user['lock_until']) > time()) {
                $formattedRemaining = Utils::formatRemainingLockTime($user['lock_until']);
                return Response::error(
                    "Account locked. Try again in $formattedRemaining (mm:ss)",
                    StatusCode::FORBIDDEN,
                    null,
                    ['remaining_attempts' => 0]
                );
            }

            // VERIFY PASSWORD
            if (!password_verify($data['password'], $user['password_hash'])) {
                
                $failedAttempts = $user['failed_attempts'] + 1;
                $lockUntil = $failedAttempts >= $this->maxAttempts
                    ? date('Y-m-d H:i:s', strtotime("+{$this->lockDurationMinutes} minutes"))
                    : null;

                // RECORD ATTEMPS
                $this->model->updateLoginAttempts(
                    $user['user_id'],
                    $failedAttempts,
                    $lockUntil
                );

                // ALERT MESSAGE
                $remainingAttempts = Utils::remainingAttempts($failedAttempts, $this->maxAttempts);
                $message = $lockUntil
                    ? "Account locked Try again later: " . date('H:i', strtotime($lockUntil))
                    : "Invalid credentials. $remainingAttempts attempts remaining";

                return Response::error(
                    $message,
                    $lockUntil ? StatusCode::FORBIDDEN : StatusCode::UNAUTHORIZED,
                    null,
                    ['remaining_attempts' => $remainingAttempts]
                );
            }

            // RESET ATTEMPS
            $this->model->resetLoginAttempts($user['user_id']);

            // GENERATE/SAVE TOKEN
            try{
                $access = Token::generateAccessToken($user['user_id'], $user['username']);
                $refresh = Token::generateRefreshToken();
            } catch (Exception $e) {
                return Response::error("Failed to generate tokens", StatusCode::INTERNAL_SERVER_ERROR, $e);
            }

            $this->model->storeTokens(
                $user['user_id'],
                $access['token'],
                $refresh['token'],
                $access['expires_at'],
                $refresh['expires_at'],
                $data['device_info'] ?? null
            );

            return Response::success(
                [
                    'user_id'   => $user['user_id'],
                    'username'  => $user['username'],
                    'access_token'  => $access['token'],
                    'refresh_token' => $refresh['token'],
                    'expires_in'    => $access['expires_at'],
                    'refresh_expires_in' => $refresh['expires_at'] - time() 
                ],
                "Welcome {$user['username']}",
                StatusCode::OK
            );

        } catch (InvalidArgumentException $e) {
            return Response::validationError(['input' => $e->getMessage()], "Validation failed", StatusCode::UNPROCESSABLE_ENTITY);
        } catch (Exception $e) {
            //error_log("Error during login: " . $e->getMessage());
            return Response::error("Failed to process login", StatusCode::INTERNAL_SERVER_ERROR, $e);
        }
    }

    public function logout($data)
    {
        try {
            $userId = $data['user_id'] ?? null;

            if (!Utils::validateId($userId)) {
                return Response::error("Invalid user ID", StatusCode::BAD_REQUEST);
            }

            $success = $this->model->clearTokens($userId);

            return $success
                ? Response::success([], "Logout successful")
                : Response::error("Logout failed or locked account", StatusCode::NOT_FOUND);
        } catch (Throwable $e) {
            return Response::error("Failed to logout", StatusCode::INTERNAL_SERVER_ERROR, $e->getMessage());
        }
    }

    public function refreshToken($data)
    {
        try {
            $tokenData = $this->model->findByRefreshToken($data['refresh_token']);
            if (!$tokenData) {
                Response::error("Invalid refresh token", StatusCode::UNAUTHORIZED);
            }

            if (strtotime($tokenData['refresh_expiry']) < time()) {
                Response::error("Refresh token expired", StatusCode::UNAUTHORIZED);
            }

            $access  = Token::generateAccessToken($tokenData['user_id'], $tokenData['username']);
            $refresh = Token::generateRefreshToken();

            $success = $this->model->updateAccessAndRefreshToken(
                $tokenData['user_id'],
                $access['token'],
                $access['expires_at'],
                $refresh['token'],
                $refresh['expires_at'],
                $tokenData['device_info']
            );

            $success
                ? Response::success([
                    'jwt' => $access['token'],
                    'expires_at' => $access['expires_at'],
                    'refresh_token' => $refresh['token'],
                    'refresh_expires_at' => $refresh['expires_at']
                ], "Token refreshed successfully")
                : Response::error("Token refresh failed", StatusCode::INTERNAL_SERVER_ERROR);

        } catch (Throwable $e) {
            Response::error("Failed to refresh token", StatusCode::INTERNAL_SERVER_ERROR, $e->getMessage());
        }
    }

    public function getUserActivity($userId)
    {
        try {
            if (!Utils::validateId($userId)) {
                return Response::error("Invalid user ID", StatusCode::BAD_REQUEST);
            }

            $page = $_GET['page'] ?? 1;
            $limit = $_GET['limit'] ?? 50;

            if (!Utils::validateId($page) || !Utils::validateId($limit)) {
                return Response::error("Invalid page or limit", StatusCode::BAD_REQUEST);
            }

            $result = $this->model->getUserActivity($userId, (int)$limit, (int)$page);

            return Response::success(
                $result['data'],
                "User activity retrieved successfully",
                StatusCode::OK,
                $result['pagination']
            );
        } catch (Throwable $e) {
            return Response::error("Failed to fetch user activity", StatusCode::INTERNAL_SERVER_ERROR, $e->getMessage());
        }
    }

    public function batchCreateUsers($data)
    {
        try {
            if (!is_array($data) || empty($data)) {
                return Response::error("Invalid batch data", StatusCode::BAD_REQUEST);
            }

            // Pre-process each user before sending to model
            $users = [];
            foreach ($data as $item) 
            {
                // Validate required fields
                $errors = Utils::requireFields($item, ['username', 'password', 'email']);
                if (!empty($errors)) {
                    return Response::validationError($errors, "Validation failed", StatusCode::UNPROCESSABLE_ENTITY);
                }

                // Validate email format
                if (!Utils::validateEmail($item['email'])) {
                    return Response::error("Invalid email format for {$item['username']}", StatusCode::BAD_REQUEST);
                }

                // Check for duplicates
                if ($this->model->findByUsername($item['username'])) {
                    return Response::error("Username {$item['username']} already exists", StatusCode::CONFLICT);
                }
                if ($this->model->findByEmail($item['email'])) {
                    return Response::error("Email {$item['email']} already exists", StatusCode::CONFLICT);
                }

                // Prepare user record
                $item['password_hash'] = Utils::hashPassword($item['password']);
                unset($item['password']);

                $users[] = $item;
            }

            // Call model bulk insert
            $result = $this->model->bulkCreateUsers($users);

            return Response::success(
                $result,
                "Batch create complete",
                StatusCode::CREATED
            );

        } catch (Throwable $e) {
            return Response::error("Batch create failed", StatusCode::INTERNAL_SERVER_ERROR, $e->getMessage());
        }
    }

    public function batchUpdateUsers($data)
    {
        try {
            if (!is_array($data) || empty($data)) {
                return Response::error("Invalid batch data", StatusCode::BAD_REQUEST);
            }

            $prepared = [];
            $results  = [];

            foreach ($data as $item) {
                if (!isset($item['id'])) {
                    $results[] = ['success' => false, 'error' => "Missing user ID"];
                    continue;
                }

                // Email validation
                if (isset($item['email']) && !Utils::validateEmail($item['email'])) {
                    $results[] = ['id' => $item['id'], 'success' => false, 'error' => "Invalid email format"];
                    continue;
                }

                // Password hashing
                if (isset($item['password'])) {
                    $item['password_hash'] = Utils::hashPassword($item['password']);
                    unset($item['password']);
                }

                $prepared[] = $item;
            }

            if (empty($prepared)) {
                return Response::error("No valid updates", StatusCode::BAD_REQUEST);
            }

            // 🔹 Use bulk update for large sets, else fall back to per-user update
            if (count($prepared) > 5) {
                $affected = $this->model->bulkUpdateUsers($prepared);
                return Response::success(['affected' => $affected], "Bulk update complete");
            } else {
                foreach ($prepared as $item) {
                    $ok = $this->model->updateUser($item['id'], $item);
                    $results[] = ['id' => $item['id'], 'success' => $ok];
                }
                return Response::success($results, "Batch update complete");
            }

        } catch (Throwable $e) {
            return Response::error("Batch update failed", StatusCode::INTERNAL_SERVER_ERROR, $e->getMessage());
        }
    }

    public function batchDeleteUsers($data)
    {
        try {
            if (!is_array($data) || empty($data)) {
                return Response::error("Invalid delete request", StatusCode::BAD_REQUEST);
            }

            $ids = [];
            foreach ($data as $item) {
                if (!isset($item['id']) || !Utils::validateId($item['id'])) {
                    return Response::error("Invalid user ID in request", StatusCode::BAD_REQUEST);
                }
                $ids[] = (int) $item['id'];
            }

            if (empty($ids)) {
                return Response::error("No valid user IDs provided", StatusCode::BAD_REQUEST);
            }

            $affected = $this->model->bulkDeleteUsers($ids);

            return Response::success(
                ['deleted' => $affected],
                "Batch delete complete"
            );

        } catch (Throwable $e) {
            return Response::error("Batch delete failed", StatusCode::INTERNAL_SERVER_ERROR, $e->getMessage());
        }
    }

}
