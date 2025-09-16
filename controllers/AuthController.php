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

    public function registerUser(array $data): array
    {
        try {
            // Validate input
            $errors = Utils::requireFields($data, ['username', 'password', 'email']);
            if (!empty($errors)) {
                return Response::validationError($errors, "Validation failed", StatusCode::UNPROCESSABLE_ENTITY);
            }

            if (!Utils::validateEmail($data['email'])) {
                return Response::error("Invalid email format", StatusCode::BAD_REQUEST);
            }

            // Hash password and remove plaintext
            $data['password_hash'] = Utils::hashPassword($data['password']);
            unset($data['password']);

            // Create user
            $result = $this->model->createUser($data);

            if (!$result['success']) {
                $statusCode = match ($result['error']) {
                    'Username is already taken', 'Email is already in use' => StatusCode::CONFLICT,
                    default => StatusCode::INTERNAL_SERVER_ERROR
                };
                return Response::error($result['error'], $statusCode);
            }

            return Response::success(
                $result['data'],
                "User created successfully",
                StatusCode::CREATED
            );
        } catch (Throwable $e) {
            return Response::error("Failed to register user", StatusCode::INTERNAL_SERVER_ERROR, $e);
        }
    }

    public function updateUserById(int $id, array $data)
    {
        try {
            if (!Utils::validateId($id)) {
                return Response::error("Invalid user ID", StatusCode::BAD_REQUEST);
            }

            if (isset($data['email'])) {
                if (!Utils::validateEmail($data['email'])) {
                    return Response::error("Invalid email format", StatusCode::BAD_REQUEST);
                }
            }

            if (isset($data['password'])) {
                $data['password_hash'] = Utils::hashPassword($data['password']);
                unset($data['password']);
            }

            $result = $this->model->updateUser($id, $data);

            if ($result['success']) {
                return Response::success([], "User updated successfully");
            }

            $statusCode = match ($result['error']) {
                'Username is already taken', 'Email is already in use' => StatusCode::CONFLICT,
                'User not found or no changes applied' => StatusCode::NOT_FOUND,
                default => StatusCode::INTERNAL_SERVER_ERROR
            };

            return Response::error($result['error'], $statusCode);
        } catch (Throwable $e) {
            return Response::error(
                "Failed to update user",
                StatusCode::INTERNAL_SERVER_ERROR,
                $e->getMessage()
            );
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

    public function login($data): array
    {
        try {
            // Validation
            $errors = Utils::requireFields($data, ['username', 'password']);
            if (!empty($errors)) {
                return Response::validationError($errors, "Validation failed", StatusCode::UNPROCESSABLE_ENTITY);
            }

            // Get user
            $user = $this->model->findByUsername($data['username']);
            if ($user === null || !password_verify($data['password'], $user['password_hash'])) {
                return $this->handleInvalidCredentials($user);
            }

            // Check account status
            if (!empty($user['deleted_at'])) {
                return Response::error("Your account has been deleted. Contact system admin", StatusCode::FORBIDDEN);
            }
            if (!$user['is_approved']) {
                return Response::error("Your account is not approved yet. Contact system admin", StatusCode::FORBIDDEN);
            }
            if ($user['is_online']) {
                return Response::error("User already logged in on another device", StatusCode::FORBIDDEN);
            }
            if (!empty($user['lock_until']) && strtotime($user['lock_until']) > time()) {
                $formattedRemaining = Utils::formatRemainingLockTime($user['lock_until']);
                return Response::error(
                    "Account locked. Try again in $formattedRemaining (mm:ss)",
                    StatusCode::FORBIDDEN,
                    null,
                    ['remaining_attempts' => 0]
                );
            }
            // Reset attempts if needed
            if ($user['failed_attempts'] > 0 || !empty($user['lock_until'])) {
                $this->model->resetLoginAttempts($user['user_id']);
            }

            // Generate and store tokens
            $access = Token::generateAccessToken($user['user_id'], $user['username']);
            $refresh = Token::generateRefreshToken();
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
                    'user_id' => $user['user_id'],
                    'username' => $user['username'],
                    'access_token' => $access['token'],
                    'refresh_token' => $refresh['token'],
                    'expires_in' => $access['expires_at'],
                    'refresh_expires_in' => $refresh['expires_at'] - time()
                ],
                "Welcome {$user['username']}",
                StatusCode::OK
            );
            
        } catch (InvalidArgumentException $e) {
            return Response::validationError(['input' => $e->getMessage()], "Validation failed", StatusCode::UNPROCESSABLE_ENTITY);
        } catch (Exception $e) {
            return Response::error("Failed to process login", StatusCode::INTERNAL_SERVER_ERROR, $e);
        }
    }

    public function logout($data)
    {
        try {
            $userId = isset($data['user_id']) ? (int)$data['user_id'] : null;

            /* For JWT Auth
            if (!Utils::validateId($userId)) {
                return Response::error("Invalid user ID", StatusCode::BAD_REQUEST);
            }*/

            $success = $this->model->clearTokens($userId);

            return $success['success']
                ? Response::success([], "Logout successful")
                : Response::error($success['message'] ?? "Logout failed or user already offline", StatusCode::NOT_FOUND);
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
            $lockUntil ? StatusCode::FORBIDDEN : StatusCode::UNAUTHORIZED,
            null,
            ['remaining_attempts' => $remainingAttempts]
        );
    }
}
