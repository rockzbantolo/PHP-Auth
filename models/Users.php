<?php
namespace Mws\Models;

use Mws\Core\Connection;
use Mws\Core\Base;
use Mws\Helpers\Utils;

use InvalidArgumentException;
use RuntimeException;
use mysqli_sql_exception;
use Throwable;
use Exception;
use mysqli;

class Users extends Base // Extend to Database
{

    /**
     * Put all required fields that will be used
     */
    private const USER_TYPES = [
        'username'          => 's',
        'email'             => 's',
        'password_hash'     => 's',
        'secret_pass'       => 's',
        'first_name'        => 's',
        'last_name'         => 's',
        'is_two_factor'     => 'i',
        'is_online'         => 'i',
        'is_approved'       => 'i',
        'is_active'         => 'i',
        'last_login'        => 's',
        'last_logout'       => 's',
        'failed_attempts'   => 'i',
        'lock_until'        => 's',
        'last_ip_address'   => 's',
    ];

    public function findAllUsers(int $page = 1, int $limit = 10): array
    {
        $offset = ($page - 1) * $limit;
        $conn = Connection::getInstance();
        $response = ['success' => false, 'data' => [], 'pagination' => null, 'error' => null];

        try {
            $stmt = "
                SELECT user_id, username, email,
                    CONCAT(first_name, ' ', last_name) AS full_name,
                    last_ip_address, last_login, is_online, is_active, created_at
                FROM users
                WHERE deleted_at IS NULL
                ORDER BY user_id DESC
                LIMIT ? OFFSET ?
            ";

            $result = $this->runQuery($conn, $stmt, "ii", [$limit, $offset]);

            if (!$result['success']) {
                $response['error'] = $result['error'] ?? 'Query failed';
                return $response;
            }

            $response['success'] = true;
            $response['data'] = $result['data'] ?? [];
            $response['pagination'] = $this->buildPagination($this->getTotalCount(), $page, $limit);
        } catch (Exception $e) {
            $response['error'] = $e->getMessage();
        } finally {
            Connection::release($conn);
        }

        return $response;
    }

    public function findUserById(int $id): ?array
    {
        $conn = Connection::getInstance();
        try {
            $stmt = "SELECT user_id, username, email, first_name, last_name,
                            last_ip_address, last_login, last_logout, failed_attempts,
                            lock_until, is_two_factor, is_online, is_approved,
                            is_active, created_at, updated_at
                    FROM users
                    WHERE user_id = ? AND deleted_at IS NULL
                    LIMIT 1";

            $result = $this->runQuery($conn, $stmt, "i", [$id]);

            if (!$result['success']) {
                throw new Exception($result['error'] ?? 'Query failed');
            }

            return $result['data'][0] ?? null;
        } catch (Exception $e) {
            throw new Exception("Failed to fetch user: " . $e->getMessage());
        } finally {
            Connection::release($conn);
        }
    }

    public function findByUsername(string $username): ?array
    {
        $conn = Connection::getInstance();
        try {
            $stmt = "
                SELECT user_id, username, password_hash, failed_attempts,
                    lock_until, is_two_factor, is_online, is_approved, is_active, deleted_at
                FROM users
                WHERE username = ?
                LIMIT 1";

            $result = $this->runQuery($conn, $stmt, "s", [$username]);

            if (!$result['success']) {
                throw new Exception($result['error'] ?? 'Query failed');
            }

            return $result['data'][0] ?? null;
        } catch (Exception $e) {
            throw new Exception("Failed to fetch user: " . $e->getMessage());
        } finally {
            Connection::release($conn);
        }
    }

    public function findByEmail(string $email): ?array
    {
        $conn = Connection::getInstance();
        try {
            $stmt = "
                SELECT user_id, username, email, password_hash, failed_attempts,
                    lock_until, is_two_factor, is_online, is_approved, is_active
                FROM users
                WHERE email = ? AND deleted_at IS NULL
                LIMIT 1";

            $result = $this->runQuery($conn, $stmt, "s", [$email]);

            if (!$result['success']) {
                throw new Exception($result['error'] ?? 'Query failed');
            }

            return $result['data'][0] ?? null;
        } catch (Exception $e) {
            throw new Exception("Failed to fetch user by email: " . $e->getMessage());
        } finally {
            Connection::release($conn);
        }
    }

    /**
     * Creates a new user.
     *
     * @param array $data User data to insert
     * @return array Returns ['success' => bool, 'data' => array|null, 'error' => string|null]
     * @throws InvalidArgumentException If input data is invalid
     * @throws mysqli_sql_exception If database operations fail
     */
    public function createUser(array $data): array
    {
        try {
                return $this->transact(function ($conn) use ($data) {
                    
                    $allowed = ['username', 'email', 'password_hash', 'first_name', 'last_name'];
                    $stmtParts = $this->prepareSqlFields($data, $allowed, self::USER_TYPES);

                    $stmt = sprintf(
                        "INSERT INTO users (%s) VALUES (%s)",
                        implode(', ', $stmtParts['fields']),
                        implode(', ', $stmtParts['placeholders'])
                    );

                    $result = $this->runQuery($conn, $stmt, $stmtParts['types'], $stmtParts['params']);
                    if (!$result['success']) {
                        return ['success' => false, 'data' => null, 'error' => $result['error'] ?? 'Query failed'];
                    }

                    $insertId = $result['insert_id'];
                    $this->logUserAction($conn, $insertId, 'ACCOUNT_CREATED', ['action' => 'User account created']);

                    return [
                        'success' => true,
                        'data' => [
                            'id' => $insertId,
                            'username' => $data['username'],
                            'email' => $data['email']
                        ],
                        'error' => null
                    ];
                });

            } catch (mysqli_sql_exception $e) {
            if ($e->getCode() === 1062) {
                $msg = str_contains($e->getMessage(), 'username')
                    ? 'Username is already taken'
                    : (str_contains($e->getMessage(), 'email')
                        ? 'Email is already in use'
                        : 'Duplicate entry');
                return ['success' => false, 'data' => null, 'error' => $msg];
            }
            return ['success' => false, 'data' => null, 'error' => $e->getMessage()];
        } catch (Throwable $e) {
            return ['success' => false, 'data' => null, 'error' => $e->getMessage()];
        }
    }

    /**
     * Updates a user.
     *
     * @param int $id User ID
     * @param array $data Fields to update
     * @return array Returns ['success' => bool, 'data' => array|null, 'error' => string|null]
     * @throws InvalidArgumentException If input data is invalid
     * @throws mysqli_sql_exception If database operations fail
     */
    public function updateUser(int $id, array $data): array
    {
        try {
            return $this->transact(function ($conn) use ($id, $data): array {
                $stmtParts = $this->prepareSqlFields($data, array_keys(self::USER_TYPES), self::USER_TYPES);

                if (empty($stmtParts['set'])) {
                    return ['success' => false, 'data' => null, 'error' => 'No valid fields provided for update'];
                }

                $stmtParts['set'][]   = 'updated_at = NOW()';
                $stmtParts['params'][] = $id;
                $stmtParts['types']  .= 'i';

                $stmt = 'UPDATE users SET ' . implode(', ', $stmtParts['set']) . 
                        ' WHERE user_id = ? AND deleted_at IS NULL';

                $result = $this->runQuery($conn, $stmt, $stmtParts['types'], $stmtParts['params']);

                if ($result['affected_rows'] === 0) {
                    return ['success' => false, 'data' => null, 'error' => 'User not found or no changes applied'];
                }

                // Decide action type
                $logAction = match (true) {
                    isset($data['password_hash']) => 'PASSWORD_CHANGE',
                    isset($data['is_two_factor']) => $data['is_two_factor'] ? '2FA_ENABLED' : '2FA_DISABLED',
                    isset($data['lock_until'])    => $data['lock_until'] ? 'ACCOUNT_LOCKED' : 'ACCOUNT_UNLOCKED',
                    default                       => 'ACCOUNT_UPDATED',
                };

                $this->logUserAction($conn, $id, $logAction, ['action' => 'User account updated']);

                return ['success' => true, 'data' => ['id' => $id], 'error' => null];
            });

        } catch (mysqli_sql_exception $e) {
            if ($e->getCode() === 1062) {
                $msg = str_contains($e->getMessage(), 'username')
                    ? 'Username is already taken'
                    : (str_contains($e->getMessage(), 'email')
                        ? 'Email is already in use'
                        : 'Duplicate entry');
                return ['success' => false, 'data' => null, 'error' => $msg];
            }
            return ['success' => false, 'data' => null, 'error' => $e->getMessage()];
        } catch (Throwable $e) {
            return ['success' => false, 'data' => null, 'error' => $e->getMessage()];
        }
    }


    public function deleteUser(int $id): array
    {
        try {
            return $this->transact(function ($conn) use ($id): array {
                $stmt   = "UPDATE users SET deleted_at = NOW() WHERE user_id = ? AND deleted_at IS NULL";
                $result = $this->runQuery($conn, $stmt, "i", [$id]);

                if ($result['affected_rows'] === 0) {
                    return ['success' => false, 'data' => null, 'error' => 'User not found or already deleted'];
                }

                $this->logUserAction($conn, $id, 'ACCOUNT_DELETED', ['action' => 'User account soft-deleted']);

                return ['success' => true, 'data' => ['id' => $id], 'error' => null];
            });
        } catch (Throwable $e) {
            return ['success' => false, 'data' => null, 'error' => $e->getMessage()];
        }
    }

    // ----------------------
    // BATCH APPROACH
    // ----------------------
    /**
     * Batch creates multiple users in a single transaction.
     *
     * @param array $users Array of user data
     * @return array
     * @throws InvalidArgumentException
     * @throws RuntimeException
     */
    public function bulkCreateUsers(array $users): array
    {
        if (empty($users)) {
            throw new InvalidArgumentException('Users array cannot be empty.');
        }

        return $this->transact(function ($conn) use ($users) {
            $userValues = [];
            $types = '';
            $params = [];
            $fields = [];

            foreach ($users as $index => $user) {
                if (!is_array($user)) {
                    throw new InvalidArgumentException("User data at index $index must be an array.");
                }
                if (!isset($user['username'], $user['email'], $user['password_hash'])) {
                    throw new InvalidArgumentException("Missing required fields for user at index $index.");
                }

                $sqlFields = $this->prepareSqlFields($user, array_keys(self::USER_TYPES), self::USER_TYPES);

                if (empty($fields)) {
                    $fields = $sqlFields['fields']; // Only need fields from first iteration
                }

                $userValues[] = '(' . implode(', ', $sqlFields['placeholders']) . ')';
                $types .= $sqlFields['types'];
                $params = array_merge($params, $sqlFields['params']);
            }

            $stmt = sprintf(
                'INSERT INTO users (%s) VALUES %s',
                implode(', ', $fields),
                implode(', ', $userValues)
            );

            $result = $this->runQuery($conn, $stmt, $types, $params);
            $firstId = $result['insert_id'] ?? 0;
            $insertedCount = $result['affected_rows'] ?? 0;

            // Collect all created IDs
            $createdUsers = [];
            for ($i = 0; $i < $insertedCount; $i++) {
                $createdUsers[] = $firstId + $i;
            }

            // Log the batch creation in one call
            $details = [
                'inserted_user_ids' => $createdUsers,
                'users_data'        => array_slice($users, 0, $insertedCount)
            ];

            $this->logUserAction($conn, 0, 'USERS_CREATED_BATCH', $details);

            return [
                'success' => true,
                'created_ids' => $createdUsers,
                'count' => $insertedCount
            ];
        });
    }

    /**
     * Batch updates multiple users in a single transaction.
     *
     * @param array $users Array of user data with 'id'
     * @return array
     * @throws InvalidArgumentException
     * @throws RuntimeException
     */
    public function bulkUpdateUsers(array $users): array
    {
        if (empty($users)) {
            throw new InvalidArgumentException('Users array cannot be empty.');
        }

        return $this->transact(function ($conn) use ($users) {
            $updatedIds = [];
            $allUpdates = [];

            foreach ($users as $index => $user) {
                if (!is_array($user)) {
                    throw new InvalidArgumentException("User data at index $index must be an array.");
                }
                if (!isset($user['id'])) {
                    throw new InvalidArgumentException("User ID is required for update at index $index.");
                }

                $sqlFields = $this->prepareSqlFields($user, array_keys(self::USER_TYPES), self::USER_TYPES);
                if (empty($sqlFields['set'])) {
                    throw new InvalidArgumentException("No valid fields to update for user at index $index.");
                }

                $sql = sprintf(
                    'UPDATE users SET %s, updated_at = NOW() WHERE user_id = ? AND deleted_at IS NULL',
                    implode(', ', $sqlFields['set'])
                );

                $types = $sqlFields['types'] . 'i';
                $params = array_merge($sqlFields['params'], [$user['id']]);

                $this->runQuery($conn, $sql, $types, $params);

                $updatedIds[] = $user['id'];
                $allUpdates[$user['id']] = $user; // Store data for batch log
            }

            // Single batch log
            $details = [
                'updated_user_ids' => $updatedIds,
                'users_data'       => $allUpdates
            ];
            $this->logUserAction($conn, 0, 'USERS_UPDATED_BATCH', $details);

            return [
                'success' => true,
                'updated_ids' => $updatedIds,
                'count' => count($updatedIds)
            ];
        });
    }

    /**
     * Batch deletes multiple users in a single transaction.
     *
     * @param array $userIds Array of user IDs
     * @return array
     * @throws InvalidArgumentException
     * @throws RuntimeException
     */
    public function bulkDeleteUsers(array $userIds): array
    {
        if (empty($userIds)) {
            throw new InvalidArgumentException('User IDs array cannot be empty.');
        }

        return $this->transact(function ($conn) use ($userIds) {
            $validatedIds = array_filter($userIds, 'is_numeric');
            if (empty($validatedIds)) {
                throw new InvalidArgumentException('No valid numeric user IDs provided.');
            }

            $placeholders = implode(',', array_fill(0, count($validatedIds), '?'));
            $sql = "DELETE FROM users WHERE user_id IN ($placeholders)";
            $types = str_repeat('i', count($validatedIds));

            $this->runQuery($conn, $sql, $types, array_values($validatedIds));

            $deletedCount = $conn->affected_rows;
            $deletedIds = array_slice(array_values($validatedIds), 0, $deletedCount);

            // Single batch log
            $details = [
                'deleted_user_ids' => $deletedIds
            ];
            $this->logUserAction($conn, 0, 'USERS_DELETED_BATCH', $details);

            return [
                'success' => true,
                'deleted_ids' => $deletedIds,
                'count' => $deletedCount
            ];
        });
    }

    /**
     * Batch soft-deletes multiple users by setting deleted_at.
     *
     * @param array $userIds Array of user IDs to soft-delete
     * @return array
     * @throws InvalidArgumentException
     * @throws RuntimeException
     */
    public function bulkSoftDeleteUsers(array $userIds): array
    {
        if (empty($userIds)) {
            throw new InvalidArgumentException('User IDs array cannot be empty.');
        }

        // Ensure 'deleted_at' type is defined
        if (!isset(self::USER_TYPES['deleted_at'])) {
            throw new InvalidArgumentException("Missing type mapping for field 'deleted_at' in USER_TYPES.");
        }

        return $this->transact(function ($conn) use ($userIds) {

            $validatedIds = array_filter($userIds, 'is_numeric');
            if (empty($validatedIds)) {
                throw new InvalidArgumentException('No valid numeric user IDs provided.');
            }

            $placeholders = implode(',', array_fill(0, count($validatedIds), '?'));
            $sql = "UPDATE users SET deleted_at = ? WHERE user_id IN ($placeholders)";
            $types = self::USER_TYPES['deleted_at'] . str_repeat('i', count($validatedIds));
            $params = array_merge([date('Y-m-d H:i:s')], array_values($validatedIds));

            $this->runQuery($conn, $sql, $types, $params);

            $updatedCount = $conn->affected_rows;
            $updatedIds = array_slice(array_values($validatedIds), 0, $updatedCount);

            // Single log entry for batch soft-delete
            $details = [
                'soft_deleted_user_ids' => $updatedIds
            ];
            $this->logUserAction($conn, 0, 'USERS_SOFT_DELETED_BATCH', $details);

            return [
                'success' => true,
                'updated_ids' => $updatedIds,
                'count' => $updatedCount
            ];
        });
    }

    // ----------------------
    // LOGIN ATTEMPTS
    // ----------------------
    public function updateLoginAttempts(int $userId, int $failedAttempts, ?string $lockUntil = null): array
    {
        try {
            return $this->transact(function ($conn) use ($userId, $failedAttempts, $lockUntil): array {
                $stmt = "
                    UPDATE users
                    SET failed_attempts = ?, lock_until = ?, last_ip_address = ?
                    WHERE user_id = ? AND deleted_at IS NULL
                ";

                $result = $this->runQuery($conn, $stmt, "issi", [
                    $failedAttempts,
                    $lockUntil,
                    Utils::getClientIp(),
                    $userId
                ]);

                if ($result['affected_rows'] === 0) {
                    return ['success' => false, 'data' => null, 'error' => 'User not found'];
                }

                $action  = $lockUntil ? 'ACCOUNT_LOCKED' : 'LOGIN_ATTEMPT';
                $details = $lockUntil
                    ? ['reason' => 'Too many failed attempts']
                    : ['attempt_count' => $failedAttempts];

                $this->logUserAction($conn, $userId, $action, $details);

                return ['success' => true, 'data' => null, 'error' => null];
            });
        } catch (Throwable $e) {
            return ['success' => false, 'data' => null, 'error' => $e->getMessage()];
        }
    }

    public function resetLoginAttempts(int $userId): array
    {
        try {
            return $this->transact(function ($conn) use ($userId): array {
                $stmt = "
                    UPDATE users
                    SET failed_attempts = 0, lock_until = NULL
                    WHERE user_id = ? AND deleted_at IS NULL
                ";

                $result = $this->runQuery($conn, $stmt, "i", [$userId]);

                if ($result['affected_rows'] === 0) {
                    return ['success' => false, 'data' => null, 'error' => 'User not found'];
                }

                $this->logUserAction($conn, $userId, 'ACCOUNT_UNLOCKED', [
                    'action' => 'Login attempts reset'
                ]);

                return ['success' => true, 'data' => null, 'error' => null];
            });
        } catch (Throwable $e) {
            return ['success' => false, 'data' => null, 'error' => $e->getMessage()];
        }
    }

    public function storeTokens(int $userId, string $jwt, string $refreshToken, int $expire, int $refreshExpire): array
    {
        try {
            return $this->transact(function ($conn) use ($userId, $jwt, $refreshToken, $expire, $refreshExpire): array {
                $deviceInfo = Utils::getDeviceInfo();

                $stmt = "
                    INSERT INTO user_tokens (user_id, jwt_token, refresh_token, token_expiry, refresh_expiry, device_info)
                    VALUES (?, ?, ?, FROM_UNIXTIME(?), FROM_UNIXTIME(?), ?)
                ";

                $result = $this->runQuery($conn, $stmt, "issiis", [
                    $userId, $jwt, $refreshToken, $expire, $refreshExpire, $deviceInfo
                ]);

                if (!$result['success']) {
                    return ['success' => false, 'data' => null, 'error' => 'Failed to store tokens'];
                }

                $update = "
                    UPDATE users
                    SET last_login = NOW(), is_online = 1, last_ip_address = ?
                    WHERE user_id = ? AND deleted_at IS NULL
                ";
                $this->runQuery($conn, $update, "si", [Utils::getClientIp(), $userId]);

                $this->logUserAction($conn, $userId, 'LOGIN', [
                    'action' => 'User logged in',
                    'device' => $deviceInfo
                ]);

                return ['success' => true, 'data' => null, 'error' => null];
            });
        } catch (Throwable $e) {
            return ['success' => false, 'data' => null, 'error' => $e->getMessage()];
        }
    }

    public function clearTokens(int $userId): array
    {
        try {
            return $this->transact(function ($conn) use ($userId): array {
                
                $stmtCheck = "SELECT is_online FROM users WHERE user_id = ? AND deleted_at IS NULL LIMIT 1";
                $result    = $this->runQuery($conn, $stmtCheck, "i", [$userId], true);
                $user      = $result['data'][0] ?? null;

                if (!$user) {
                    return ['success' => false, 'data' => null, 'error' => 'User not found'];
                }

                if ((int)$user['is_online'] !== 1) {
                    return ['success' => false, 'data' => null, 'error' => 'User is not online'];
                }

                $stmt   = "DELETE FROM user_tokens WHERE user_id = ?";
                $result = $this->runQuery($conn, $stmt, "i", [$userId]);

                if ($result['affected_rows'] === 0) {
                    return ['success' => false, 'data' => null, 'error' => 'No tokens found'];
                }

                $update = "
                    UPDATE users
                    SET is_online = 0, last_logout = NOW(), last_ip_address = ?
                    WHERE user_id = ? AND deleted_at IS NULL
                ";
                $this->runQuery($conn, $update, "si", [Utils::getClientIp(), $userId]);

                $this->logUserAction($conn, $userId, 'LOGOUT', [
                    'action' => 'User logged out',
                    'user_agent' => Utils::getUserAgent(),
                    'device' => Utils::getDeviceInfo()
                ]);

                return ['success' => true, 'data' => null, 'error' => null];
            });
        } catch (Throwable $e) {
            return ['success' => false, 'data' => null, 'error' => $e->getMessage()];
        }
    }

    public function findByRefreshToken(string $refreshToken): ?array
    {
        $stmt = "SELECT ut.user_id, u.username, ut.refresh_token, ut.jwt_token,
                        ut.token_expiry, ut.refresh_expiry, ut.device_info
                FROM user_tokens ut
                JOIN users u ON u.user_id = ut.user_id
                WHERE ut.refresh_token = ?
                LIMIT 1";

        $conn = Connection::getInstance();
        $token = $this->runQuery($conn, $stmt, "s", [$refreshToken], true);
        Connection::release($conn);

        return $token['data'] ?? null;
    }

    public function updateAccessAndRefreshToken(int $userId, string $jwt, int $expire, string $refreshToken, int $refreshExpire): array
    {
        try {
            return $this->transact(function ($conn) use ($userId, $jwt, $expire, $refreshToken, $refreshExpire): array {
                $stmt = "
                    UPDATE user_tokens
                    SET jwt_token = ?, token_expiry = FROM_UNIXTIME(?),
                        refresh_token = ?, refresh_expiry = FROM_UNIXTIME(?)
                    WHERE user_id = ? AND device_info = ?
                ";

                $result = $this->runQuery($conn, $stmt, "sisiis", [
                    $jwt, $expire, $refreshToken, $refreshExpire, $userId, Utils::getDeviceInfo()
                ]);

                if ($result['affected_rows'] === 0) {
                    return ['success' => false, 'data' => null, 'error' => 'No token updated'];
                }

                return ['success' => true, 'data' => null, 'error' => null];
            });
        } catch (Throwable $e) {
            return ['success' => false, 'data' => null, 'error' => $e->getMessage()];
        }
    }

    // ----------------------
    // ACTIVITY LOGGING
    // ----------------------

    public function getUserActivity($userId, $limit = 50, $page = 1)
    {
        $stmt = "SELECT l.log_id, l.user_id, s.status_code, s.display_name AS action_name,
                        l.ip_address, l.user_agent, l.action_timestamp, l.details
                 FROM user_activity_logs l
                 JOIN statuses s ON l.status_id = s.status_id
                 WHERE l.user_id = ?
                 ORDER BY l.action_timestamp DESC
                 LIMIT ? OFFSET ?";

        $offset = ($page - 1) * $limit;
        $conn = Connection::getInstance();
        $logs = $this->runQuery($conn, $stmt, "iii", [$userId, $limit, $offset]);
        Connection::release($conn);

        $total = $this->getActivityTotalCount($userId);
        $pagination = $this->buildPagination($total, $page, $limit);

        return ['data' => $logs, 'pagination' => $pagination];
    }

    // ----------------------
    // PAGINATION HELPERS
    // ----------------------
    protected function getTotalCount(): int
    {
        $conn = Connection::getInstance();
        $stmt = "SELECT COUNT(*) AS total FROM users WHERE deleted_at IS NULL";
        $result = $this->runQuery($conn, $stmt);
        Connection::release($conn);
        return $result['data'][0]['total'] ?? 0;
    }

    public function getActivityTotalCount($userId)
    {
        $conn = Connection::getInstance();
        $stmt = "SELECT COUNT(*) as total FROM user_activity_logs WHERE user_id = ?";
        $row = $this->runQuery($conn, $stmt, "i", [$userId], true);
        Connection::release($conn);
        return (int)$row['total'];
    }

    
}
