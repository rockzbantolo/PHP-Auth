<?php
namespace Mws\Models;

use Mws\Core\Connection;
use Mws\Core\Base;
use Mws\Helpers\Utils;

use InvalidArgumentException;
use Exception;
use mysqli;

class Users extends Base // Extend to Database
{

    /**
     * Put all required fields that will be used
     */
    private const USER_TYPES = [
        'username'              => 's',
        'email'                 => 's',
        'password_hash'         => 's',
        'secret_pass'           => 's',
        'first_name'            => 's',
        'last_name'             => 's',
        'is_two_factor_enabled' => 'i',
        'is_online'             => 'i',
        'is_approved'           => 'i',
        'is_active'             => 'i',
        'last_login'            => 's',
        'last_logout'           => 's',
        'failed_attempts'       => 'i',
        'lock_until'            => 's',
        'last_ip_address'       => 's',
    ];

    // ----------------------
    // USER MANAGEMENT
    // ----------------------
    public function findAllUsers($page = 1, $limit = 10)
    {
        $stmt = "
            SELECT user_id, username, email,
                   CONCAT(first_name, ' ', last_name) AS full_name,
                   last_ip_address, last_login, is_online, is_active, created_at
            FROM users
            WHERE deleted_at IS NULL
            ORDER BY user_id DESC
            LIMIT ? OFFSET ?
        ";

        $offset = ($page - 1) * $limit;
        $conn = Connection::getInstance();
        $users = $this->fetchData($conn, $stmt, "ii", [$limit, $offset]);
        Connection::release($conn);

        $total = $this->getTotalCount();
        $pagination = $this->buildPagination($total, $page, $limit);

        return ['data' => $users ?: [], 'pagination' => $pagination];
    }

    public function findUserById($id)
    {
        $stmt = "
            SELECT user_id, username, email, first_name, last_name,
                   last_ip_address, last_login, last_logout, failed_attempts,
                   lock_until, is_two_factor_enabled, is_online, is_approved,
                   is_active, created_at, updated_at
            FROM users
            WHERE user_id = ? AND deleted_at IS NULL
        ";

        $conn = Connection::getInstance();
        $user = $this->fetchData($conn, $stmt, "i", [$id], true);
        Connection::release($conn);
        return $user ?: false;
    }

    public function findByUsername($username)
    {
        $stmt = "SELECT * FROM users WHERE username = ? AND deleted_at IS NULL";

        $conn = Connection::getInstance();
        $user = $this->fetchData($conn, $stmt, "s", [$username], true);
        Connection::release($conn);
        return $user ?: false;
    }

    public function findByEmail($email)
    {
        $stmt = "SELECT * FROM users WHERE email = ? AND deleted_at IS NULL";

        $conn = Connection::getInstance();
        $user = $this->fetchData($conn, $stmt, "s", [$email], true);
        Connection::release($conn);
        return $user ?: false;
    }

    public function createUser(array $data)
    {
        return $this->transact(function (mysqli $conn) use ($data) {
            
            $allowed = ['username', 'email', 'password_hash', 'first_name', 'last_name'];
            $stmtParts = $this->mapFields($data, $allowed, self::USER_TYPES);

            $stmt = sprintf(
                "INSERT INTO users (%s) VALUES (%s)",
                implode(', ', $stmtParts['fields']),
                implode(', ', $stmtParts['placeholders'])
            );

            $this->fetchData($conn, $stmt, $stmtParts['types'], $stmtParts['params']);
            
            $insertId = $conn->insert_id;
            $this->logUserAction($conn, $insertId, 'ACCOUNT_CREATED', ['action' => 'User account created']);

            return ['success' => true, 'id' => $insertId];
        });
    }

    public function updateUser(int $id, array $data): bool
    {
        return $this->transact(function (mysqli $conn) use ($id, $data): bool {

            $stmtParts = $this->mapFields($data, array_keys(self::USER_TYPES), self::USER_TYPES);
            if (empty($stmtParts['set'])) {
                throw new InvalidArgumentException('No valid fields provided for update.');
            }

            // Add user_id binding
            $stmtParts['params'][] = $id;
            $stmtParts['types']   .= 'i';

            $stmt = 'UPDATE users SET ' . implode(', ', $stmtParts['set']) .
                    ' WHERE user_id = ? AND deleted_at IS NULL';

            $success = $this->fetchData($conn, $stmt, $stmtParts['types'], $stmtParts['params']);

            // Optional logging
            if ($success) {
                $logAction = 'ACCOUNT_UPDATED';
                if (isset($data['password_hash'])) {
                    $logAction = 'PASSWORD_CHANGE';
                } elseif (isset($data['is_two_factor_enabled'])) {
                    $logAction = $data['is_two_factor_enabled'] ? '2FA_ENABLED' : '2FA_DISABLED';
                } elseif (isset($data['lock_until'])) {
                    $logAction = $data['lock_until'] ? 'ACCOUNT_LOCKED' : 'ACCOUNT_UNLOCKED';
                }

                if ($logAction) {
                    $this->logUserAction($conn, $id, $logAction, ['action' => 'User account updated']);
                }
            }

            return $success;
        });
    }

    public function deleteUser(int $id)
    {
        return $this->transact(function (mysqli $conn) use ($id) {
           
            // Soft delete: just update deleted_at
            $stmt = "UPDATE users SET deleted_at = NOW() WHERE user_id = ? AND deleted_at IS NULL";
            $success = $this->fetchData($conn, $stmt, "i", [$id]);

            if ($success) {
                $this->logUserAction($conn, $id, 'ACCOUNT_DELETED', null, null, [
                    'action' => 'User account soft-deleted'
                ]);
            }

            return ['success' => $success];
        });
    }


    // ----------------------
    // BATCH APPROACH
    // ----------------------
    public function bulkCreateUsers(array $users)
    {
        return $this->transact(function ($conn) use ($users) {
            $createdUsers = [];
            $userValues   = [];
            $actionValues = [];
            $types        = "";
            $params       = [];

            foreach ($users as $user) {
                if (!isset($user['username'], $user['password_hash'], $user['email'])) {
                    throw new Exception("Missing required fields for one or more users");
                }

                $userValues[] = "(?, ?, ?, ?, ?, ?, ?, ?)";
                $types       .= "sssssiii";
                $params[]     = $user['username'];
                $params[]     = $user['email'];
                $params[]     = $user['password_hash'];
                $params[]     = $user['first_name'] ?? null;
                $params[]     = $user['last_name'] ?? null;
                $params[]     = (int)($user['is_two_factor_enabled'] ?? 0);
                $params[]     = (int)($user['is_approved'] ?? 0);
                $params[]     = (int)($user['is_active'] ?? 1);
            }

            // Insert all users
            $stmt = "
                INSERT INTO users (
                    username, email, password_hash,
                    first_name, last_name,
                    is_two_factor_enabled, is_approved, is_active
                ) VALUES " . implode(", ", $userValues);

            $stmt = $conn->prepare($stmt);
            $stmt->bind_param($types, ...$params);
            $stmt->execute();

            $firstId = $stmt->insert_id;
            $insertedCount = $stmt->affected_rows;

            // Collect inserted user IDs
            for ($i = 0; $i < $insertedCount; $i++) {
                $userId = $firstId + $i;
                $createdUsers[] = $userId;

                // Prepare user_actions log values
                $actionValues[] = "($userId, 'ACCOUNT_CREATED', NULL, NULL, ?)";
                $params[] = json_encode(['action' => 'User account created']);
                $types .= "s";
            }

            // Insert logs in one go
            if (!empty($actionValues)) {
                $logstmt = "
                    INSERT INTO user_actions (
                        user_id, action_type, ip_address, user_agent, metadata
                    ) VALUES " . implode(", ", $actionValues);

                $stmt = $conn->prepare($logstmt);
                $stmt->bind_param(substr($types, -count($createdUsers)), ...array_slice($params, -count($createdUsers)));
                $stmt->execute();
            }

            return [
                'success' => true,
                'created_ids' => $createdUsers,
                'count' => $insertedCount
            ];
        });
    }

    public function bulkUpdateUsers(array $updates)
    {
        return $this->transact(function ($conn) use ($updates) {
            if (empty($updates)) {
                throw new Exception("No updates provided");
            }

            $allowed = [
                'username'              => 's',
                'email'                 => 's',
                'password_hash'         => 's',
                'secret_pass'           => 's',
                'first_name'            => 's',
                'last_name'             => 's',
                'is_two_factor_enabled' => 'i',
                'is_online'             => 'i',
                'is_approved'           => 'i',
                'is_active'             => 'i',
                'last_login'            => 's',
                'last_logout'           => 's',
                'failed_attempts'       => 'i',
                'lock_until'            => 's',
                'last_ip_address'       => 's'
            ];

            $userIds = array_column($updates, 'id');
            $cases   = [];
            $params  = [];
            $types   = "";

            foreach ($allowed as $field => $type) {
                $caseParts = [];
                foreach ($updates as $update) {
                    if (isset($update[$field])) {
                        $caseParts[] = "WHEN ? THEN ?";
                        $params[] = $update['id'];
                        $params[] = $update[$field];
                        $types   .= "i" . $type;
                    }
                }
                if (!empty($caseParts)) {
                    $cases[] = "$field = CASE user_id " . implode(" ", $caseParts) . " ELSE $field END";
                }
            }

            if (empty($cases)) {
                throw new Exception("No valid fields to update");
            }

            $placeholders = implode(",", array_fill(0, count($userIds), "?"));
            $params = array_merge($params, $userIds);
            $types .= str_repeat("i", count($userIds));

            $stmt = "UPDATE users 
                    SET " . implode(", ", $cases) . ", updated_at = NOW()
                    WHERE user_id IN ($placeholders) AND deleted_at IS NULL";

            $stmt = $conn->prepare($stmt);
            if (!$stmt) {
                throw new Exception("Failed to prepare statement: " . $conn->error);
            }

            $stmt->bind_param($types, ...$params);
            $stmt->execute();

            // 🔹 Log bulk action once (for auditing)
            foreach ($userIds as $uid) {
                $this->logUserAction($conn, $uid, 'BULK_UPDATE', null, null, ['action' => 'User updated in bulk']);
            }

            return $stmt->affected_rows;
        });
    }

    public function bulkDeleteUsers(array $ids)
    {
        return $this->transact(function ($conn) use ($ids) {
            if (empty($ids)) {
                throw new Exception("No user IDs provided for deletion");
            }

            $placeholders = implode(",", array_fill(0, count($ids), "?"));
            $types = str_repeat("i", count($ids));

            $stmt = "UPDATE users 
                    SET deleted_at = NOW(), updated_at = NOW() 
                    WHERE user_id IN ($placeholders) AND deleted_at IS NULL";

            $stmt = $conn->prepare($stmt);
            if (!$stmt) {
                throw new Exception("Failed to prepare statement: " . $conn->error);
            }

            $stmt->bind_param($types, ...$ids);
            $stmt->execute();

            // Log per user
            foreach ($ids as $uid) {
                $this->logUserAction($conn, $uid, 'ACCOUNT_DELETED', null, null, ['action' => 'User soft-deleted']);
            }

            return $stmt->affected_rows;
        });
    }

    // ----------------------
    // LOGIN ATTEMPTS
    // ----------------------
    public function updateLoginAttempts($userId, $failedAttempts, $lockUntil = null)
    {
        return $this->transact(function ($conn) use ($userId, $failedAttempts, $lockUntil) {
            
            $stmt = "
                UPDATE users
                SET failed_attempts = ?, lock_until = ?, last_ip_address = ?
                WHERE user_id = ? AND deleted_at IS NULL";

            $success = $this->fetchData($conn, $stmt, "issi", [$failedAttempts, $lockUntil, Utils::getClientIp(), $userId]);
            if ($success) {
                $action  = $lockUntil ? 'ACCOUNT_LOCKED' : 'LOGIN_ATTEMPT';
                $details = $lockUntil ? ['reason' => 'Too many failed attempts'] : ['attempt_count' => $failedAttempts];
                $this->logUserAction($conn, $userId, $action, $details);
            }

            return $success;
        });
    }


    public function resetLoginAttempts($userId)
    {
        return $this->transact(function ($conn) use ($userId) {
           
            $stmt = "
                UPDATE users
                SET failed_attempts = 0, lock_until = NULL
                WHERE user_id = ? AND deleted_at IS NULL";

            $success = $this->fetchData($conn, $stmt, "i", [$userId]);
            if ($success) {
                $this->logUserAction($conn, $userId, 'ACCOUNT_UNLOCKED', ['action' => 'Login attempts reset']);
            }

            return $success;
        });
    }


    // ----------------------
    // JWT TOKENS
    // ----------------------

    // Login
    public function storeTokens($userId, $jwt, $refreshToken, $expire, $refreshExpire)
    {
        return $this->transact(function ($conn) use ($userId, $jwt, $refreshToken, $expire, $refreshExpire) {
            
            $deviceInfo = Utils::getDeviceInfo();
            
            $stmt = "
                INSERT INTO user_tokens (user_id, jwt_token, refresh_token, token_expiry, refresh_expiry, device_info)
                VALUES (?, ?, ?, FROM_UNIXTIME(?), FROM_UNIXTIME(?), ?)";

            $success = $this->fetchData($conn, $stmt, "issiis", [$userId, $jwt, $refreshToken, $expire, $refreshExpire, $deviceInfo]);

            if ($success) {
                $update = "
                    UPDATE users
                    SET last_login = NOW(), is_online = 1, last_ip_address = ?
                    WHERE user_id = ? AND deleted_at IS NULL";

                $this->fetchData($conn, $update, "si", [Utils::getClientIp(), $userId]);
                $this->logUserAction($conn, $userId, 'LOGIN', ['action' => 'User logged in', 'device' => $deviceInfo]);
            }
            return $success;
        });
    }

    // Logout
    public function clearTokens($userId)
    {
        return $this->transact(function ($conn) use ($userId) {

            $stmt = "DELETE FROM user_tokens WHERE user_id = ?";
            $success = $this->fetchData($conn, $stmt, "i", [$userId]);

            if ($success) {
                $update = "
                    UPDATE users
                    SET is_online = 0, last_logout = NOW(), last_ip_address = ?
                    WHERE user_id = ? AND deleted_at IS NULL";

                $this->fetchData($conn, $update, "si", [Utils::getClientIp(), $userId]);
                $this->logUserAction($conn, $userId, 'LOGOUT', ['action' => 'User logged out', 'device' => Utils::getDeviceInfo()]);
            }
            return $success;
        });
    }

    public function findByRefreshToken($refreshToken)
    {
        $stmt = "
            SELECT ut.user_id    AS user_id,
                u.username       AS username,
                ut.refresh_token AS refresh_token,
                ut.jwt_token     AS jwt_token, 
                ut.token_expiry  AS token_expiry, 
                ut.refresh_expiry AS refresh_expiry, 
                ut.device_info   AS device_info
            FROM user_tokens ut
            JOIN users u ON u.user_id = ut.user_id 
            WHERE ut.refresh_token = ?
            LIMIT 1";

        $conn = Connection::getInstance();
        $token = $this->fetchData($conn, $stmt, "s", [$refreshToken], true);
        Connection::release($conn);
        return $token;
    }

    public function updateAccessAndRefreshToken($userId, $jwt, $expire, $refreshToken, $refreshExpire)
    {
        return $this->transact(function ($conn) use ($userId, $jwt, $expire, $refreshToken, $refreshExpire) {

            $stmt = "
                UPDATE user_tokens
                SET jwt_token = ?, token_expiry = FROM_UNIXTIME(?),
                    refresh_token = ?, refresh_expiry = FROM_UNIXTIME(?)
                WHERE user_id = ? AND device_info = ?";

            return $this->fetchData($conn, $stmt, "sisiis", [$jwt, $expire, $refreshToken, $refreshExpire, $userId, Utils::getDeviceInfo()]);
        });
    }

    // ----------------------
    // ACTIVITY LOGGING
    // ----------------------
    public function logUserAction($conn, $userId, $actionCode, $details = null)
    {                 
        $stmt = "
            SELECT status_id
            FROM statuses
            WHERE status_code = ? AND category = 'USER_ACTION' AND is_active = 1
            LIMIT 1";

        $status = $this->fetchData($conn, $stmt, "s", [$actionCode], true);
        if (!$status) {
            //error_log("Warning: Invalid action code '$actionCode' for user_id $userId");
            return false;
        }

        $detailsJson = $details ? json_encode($details, JSON_UNESCAPED_SLASHES) : null;

        $insert = "
            INSERT INTO user_activity_logs (user_id, status_id, ip_address, user_agent, details)
            VALUES (?, ?, ?, ?, ?)";

        return $this->fetchData($conn, $insert, "iisss", [$userId, $status['status_id'],  Utils::getClientIp(), Utils::getUserAgent(), $detailsJson]);
    }

    public function getUserActivity($userId, $limit = 50, $page = 1)
    {
        $offset = ($page - 1) * $limit;
        $conn = Connection::getInstance();

        $stmt = "
            SELECT l.log_id, l.user_id, s.status_code, s.display_name AS action_name,
                   l.ip_address, l.user_agent, l.action_timestamp, l.details
            FROM user_activity_logs l
            JOIN statuses s ON l.status_id = s.status_id
            WHERE l.user_id = ?
            ORDER BY l.action_timestamp DESC
            LIMIT ? OFFSET ?";

        $logs = $this->fetchData($conn, $stmt, "iii", [$userId, $limit, $offset]);
        Connection::release($conn);

        $total = $this->getActivityTotalCount($userId);
        $pagination = $this->buildPagination($total, $page, $limit);

        return ['data' => $logs, 'pagination' => $pagination];
    }

    // ----------------------
    // PAGINATION HELPERS
    // ----------------------
    public function getTotalCount()
    {
        $conn = Connection::getInstance();
        $stmt = "SELECT COUNT(*) as total FROM users WHERE deleted_at IS NULL AND is_active = 1";
        $row = $this->fetchData($conn, $stmt, "", [], true);
        Connection::release($conn);
        return (int)$row['total'];
    }

    public function getActivityTotalCount($userId)
    {
        $conn = Connection::getInstance();
        $stmt = "SELECT COUNT(*) as total FROM user_activity_logs WHERE user_id = ?";
        $row = $this->fetchData($conn, $stmt, "i", [$userId], true);
        Connection::release($conn);
        return (int)$row['total'];
    }
}
