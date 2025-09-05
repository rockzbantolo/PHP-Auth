<?php
namespace Mws\Models;

use Mws\Core\Connection;
use Exception;
use Mws\Core\Base;

class Users extends Base // Extend to Database
{
    // ----------------------
    // USER MANAGEMENT
    // ----------------------
    public function findAllUsers($page = 1, $limit = 10)
    {
        $offset = ($page - 1) * $limit;
        $conn = Connection::getInstance();

        $query = "
            SELECT user_id, username, email,
                   CONCAT(first_name, ' ', last_name) AS full_name,
                   last_ip_address, last_login, is_online, is_active, created_at
            FROM users
            WHERE deleted_at IS NULL
            ORDER BY user_id DESC
            LIMIT ? OFFSET ?
        ";

        $users = $this->exQuery($conn, $query, "ii", [$limit, $offset]);
        Connection::release($conn);

        $total = $this->getTotalCount();
        $pagination = $this->buildPagination($total, $page, $limit);

        return ['data' => $users, 'pagination' => $pagination];
    }

    public function findUserById($id)
    {
        $conn = Connection::getInstance();
        $query = "
            SELECT user_id, username, email, first_name, last_name,
                   last_ip_address, last_login, last_logout, failed_attempts,
                   lock_until, is_two_factor_enabled, is_online, is_approved,
                   is_active, created_at, updated_at
            FROM users
            WHERE user_id = ? AND deleted_at IS NULL
        ";

        $user = $this->exQuery($conn, $query, "i", [$id], true);
        Connection::release($conn);
        return $user;
    }

    public function findByUsername($username)
    {
        $conn = Connection::getInstance();
        $query = "SELECT * FROM users WHERE username = ? AND is_active = 1";
        $user = $this->exQuery($conn, $query, "s", [$username], true);
        Connection::release($conn);
        return $user ?: false;
    }

    public function findByEmail($email)
    {
        $conn = Connection::getInstance();
        $query = "SELECT * FROM users WHERE email = ? AND is_active = 1";
        $user = $this->exQuery($conn, $query, "s", [$email], true);
        Connection::release($conn);
        return $user ?: false;
    }

    public function createUser($data)
    {
        return $this->exTransaction(function ($conn) use ($data) {
            $sql = "
                INSERT INTO users (
                    username, email, password_hash,
                    first_name, last_name,
                    is_two_factor_enabled, is_approved, is_active
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            ";

            $params = [
                $data['username'],
                $data['email'],
                $data['password_hash'],
                $data['first_name'] ?? null,
                $data['last_name'] ?? null,
                (int)($data['is_two_factor_enabled'] ?? 0),
                (int)($data['is_approved'] ?? 0),
                (int)($data['is_active'] ?? 1),
            ];

            $this->exQuery($conn, $sql, "sssssiii", $params);
            $insertId = $conn->insert_id;

            $this->logUserAction($conn, $insertId, 'ACCOUNT_CREATED', null, null, [
                'action' => 'User account created'
            ]);

            return ['success' => true, 'id' => $insertId];
        });
    }

    public function updateUser($id, $data)
    {
        return $this->exTransaction(function ($conn) use ($id, $data) {
            $fields = [];
            $params = [];
            $types  = "";
            $logAction = null;

            $map = [
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

            foreach ($map as $key => $type) {
                if (isset($data[$key])) {
                    $fields[] = "$key = ?";
                    $params[] = $data[$key];
                    $types .= $type;

                    if ($key === 'password_hash') $logAction = 'PASSWORD_CHANGE';
                    if ($key === 'is_two_factor_enabled') $logAction = $data[$key] ? '2FA_ENABLED' : '2FA_DISABLED';
                    if ($key === 'lock_until') $logAction = $data[$key] ? 'ACCOUNT_LOCKED' : 'ACCOUNT_UNLOCKED';
                }
            }

            if (empty($fields)) {
                throw new Exception("No fields provided for update");
            }

            $fields[] = "updated_at = NOW()";
            $params[] = $id;
            $types .= "i";

            $query = "UPDATE users SET " . implode(", ", $fields) . " WHERE user_id = ? AND deleted_at IS NULL";
            $stmt  = Connection::getCachedStatement($conn, $query) ?? $conn->prepare($query);
            if (!$stmt) {
                throw new Exception("Failed to prepare statement: " . $conn->error);
            }
            Connection::cacheStatement($conn, $query, $stmt);

            $stmt->bind_param($types, ...$params);
            $stmt->execute();
            $success = $stmt->affected_rows > 0;

            if ($success && $logAction) {
                $this->logUserAction($conn, $id, $logAction, null, null, ['action' => $logAction]);
            }

            return $success;
        });
    }

    public function deleteUser($id)
    {
        return $this->exTransaction(function ($conn) use ($id) {
            $query = "UPDATE users SET deleted_at = NOW() WHERE user_id = ? AND deleted_at IS NULL";
            $success = $this->exQuery($conn, $query, "i", [$id]);

            if ($success) {
                $this->logUserAction($conn, $id, 'ACCOUNT_DELETED', null, null, ['action' => 'User account soft-deleted']);
            }
            return ['success' => $success];
        });
    }

    // ----------------------
    // BATCH APPROACH
    // ----------------------
    public function bulkCreateUsers(array $users)
    {
        return $this->exTransaction(function ($conn) use ($users) {
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
            $query = "
                INSERT INTO users (
                    username, email, password_hash,
                    first_name, last_name,
                    is_two_factor_enabled, is_approved, is_active
                ) VALUES " . implode(", ", $userValues);

            $stmt = $conn->prepare($query);
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
                $logQuery = "
                    INSERT INTO user_actions (
                        user_id, action_type, ip_address, user_agent, metadata
                    ) VALUES " . implode(", ", $actionValues);

                $stmt = $conn->prepare($logQuery);
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
        return $this->exTransaction(function ($conn) use ($updates) {
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

            $query = "UPDATE users 
                    SET " . implode(", ", $cases) . ", updated_at = NOW()
                    WHERE user_id IN ($placeholders) AND deleted_at IS NULL";

            $stmt = $conn->prepare($query);
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
        return $this->exTransaction(function ($conn) use ($ids) {
            if (empty($ids)) {
                throw new Exception("No user IDs provided for deletion");
            }

            $placeholders = implode(",", array_fill(0, count($ids), "?"));
            $types = str_repeat("i", count($ids));

            $query = "UPDATE users 
                    SET deleted_at = NOW(), updated_at = NOW() 
                    WHERE user_id IN ($placeholders) AND deleted_at IS NULL";

            $stmt = $conn->prepare($query);
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
    public function updateLoginAttempts($userId, $failedAttempts, $lockUntil = null, $ipAddress = null, $userAgent = null)
    {
        return $this->exTransaction(function ($conn) use ($userId, $failedAttempts, $lockUntil, $ipAddress, $userAgent) {
            $query = "
                UPDATE users
                SET failed_attempts = ?, lock_until = ?, last_ip_address = ?
                WHERE user_id = ? AND deleted_at IS NULL
            ";
            $success = $this->exQuery($conn, $query, "issi", [$failedAttempts, $lockUntil, $ipAddress, $userId]);

            if ($success) {
                $action  = $lockUntil ? 'ACCOUNT_LOCKED' : 'LOGIN_ATTEMPT';
                $details = $lockUntil ? ['reason' => 'Too many failed attempts'] : ['attempt_count' => $failedAttempts];
                $this->logUserAction($conn, $userId, $action, $ipAddress, $userAgent, $details);
            }

            return $success;
        });
    }

    public function resetLoginAttempts($userId, $ipAddress = null, $userAgent = null)
    {
        return $this->exTransaction(function ($conn) use ($userId, $ipAddress, $userAgent) {
            $query = "
                UPDATE users
                SET failed_attempts = 0, lock_until = NULL
                WHERE user_id = ? AND deleted_at IS NULL
            ";
            $success = $this->exQuery($conn, $query, "i", [$userId]);

            if ($success) {
                $this->logUserAction($conn, $userId, 'ACCOUNT_UNLOCKED', $ipAddress, $userAgent, ['action' => 'Login attempts reset']);
            }

            return $success;
        });
    }

    // ----------------------
    // JWT TOKENS
    // ----------------------
    public function storeTokens($userId, $jwt, $refreshToken, $expire, $refreshExpire, $deviceInfo = null, $ipAddress = null, $userAgent = null)
    {
        return $this->exTransaction(function ($conn) use ($userId, $jwt, $refreshToken, $expire, $refreshExpire, $deviceInfo, $ipAddress, $userAgent) {
            $query = "
                INSERT INTO user_tokens (user_id, jwt_token, refresh_token, token_expiry, refresh_expiry, device_info)
                VALUES (?, ?, ?, FROM_UNIXTIME(?), FROM_UNIXTIME(?), ?)
            ";
            $success = $this->exQuery($conn, $query, "issiis", [$userId, $jwt, $refreshToken, $expire, $refreshExpire, $deviceInfo]);

            if ($success) {
                $update = "
                    UPDATE users
                    SET last_login = NOW(), is_online = 1, last_ip_address = ?
                    WHERE user_id = ? AND deleted_at IS NULL
                ";
                $this->exQuery($conn, $update, "si", [$ipAddress, $userId]);
                $this->logUserAction($conn, $userId, 'LOGIN', $ipAddress, $userAgent, ['device' => $deviceInfo]);
            }
            return $success;
        });
    }

    public function clearTokens($userId, $ipAddress = null, $userAgent = null)
    {
        return $this->exTransaction(function ($conn) use ($userId, $ipAddress, $userAgent) {
            $query = "DELETE FROM user_tokens WHERE user_id = ?";
            $success = $this->exQuery($conn, $query, "i", [$userId]);

            if ($success) {
                $update = "
                    UPDATE users
                    SET is_online = 0, last_logout = NOW(), last_ip_address = ?
                    WHERE user_id = ? AND deleted_at IS NULL
                ";
                $this->exQuery($conn, $update, "si", [$ipAddress, $userId]);
                $this->logUserAction($conn, $userId, 'LOGOUT', $ipAddress, $userAgent, ['action' => 'User logged out']);
            }
            return $success;
        });
    }

    public function findByRefreshToken($refreshToken)
    {
        $conn = Connection::getInstance();
        $query = "
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
            LIMIT 1
        ";
        $token = $this->exQuery($conn, $query, "s", [$refreshToken], true);
        Connection::release($conn);
        return $token;
    }

    public function updateAccessAndRefreshToken($userId, $jwt, $expire, $refreshToken, $refreshExpire, $deviceInfo = null)
    {
        return $this->exTransaction(function ($conn) use ($userId, $jwt, $expire, $refreshToken, $refreshExpire, $deviceInfo) {
            $query = "
                UPDATE user_tokens
                SET jwt_token = ?, token_expiry = FROM_UNIXTIME(?),
                    refresh_token = ?, refresh_expiry = FROM_UNIXTIME(?)
                WHERE user_id = ? AND device_info = ?
            ";
            return $this->exQuery($conn, $query, "sisiis", [$jwt, $expire, $refreshToken, $refreshExpire, $userId, $deviceInfo]);
        });
    }

    // ----------------------
    // ACTIVITY LOGGING
    // ----------------------
    public function logUserAction($conn, $userId, $actionCode, $ipAddress = null, $userAgent = null, $details = null)
    {
        $query = "
            SELECT status_id
            FROM statuses
            WHERE status_code = ? AND category = 'USER_ACTION' AND is_active = 1
            LIMIT 1
        ";
        $status = $this->exQuery($conn, $query, "s", [$actionCode], true);

        if (!$status) {
            error_log("Warning: Invalid action code '$actionCode' for user_id $userId");
            return false;
        }

        $detailsJson = $details ? json_encode($details) : null;

        $insert = "
            INSERT INTO user_activity_logs (user_id, status_id, ip_address, user_agent, details)
            VALUES (?, ?, ?, ?, ?)
        ";
        return $this->exQuery($conn, $insert, "iisss", [$userId, $status['status_id'], $ipAddress, $userAgent, $detailsJson]);
    }

    public function getUserActivity($userId, $limit = 50, $page = 1)
    {
        $offset = ($page - 1) * $limit;
        $conn = Connection::getInstance();

        $query = "
            SELECT l.log_id, l.user_id, s.status_code, s.display_name AS action_name,
                   l.ip_address, l.user_agent, l.action_timestamp, l.details
            FROM user_activity_logs l
            JOIN statuses s ON l.status_id = s.status_id
            WHERE l.user_id = ?
            ORDER BY l.action_timestamp DESC
            LIMIT ? OFFSET ?
        ";
        $logs = $this->exQuery($conn, $query, "iii", [$userId, $limit, $offset]);
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
        $query = "SELECT COUNT(*) as total FROM users WHERE deleted_at IS NULL AND is_active = 1";
        $row = $this->exQuery($conn, $query, "", [], true);
        Connection::release($conn);
        return (int)$row['total'];
    }

    public function getActivityTotalCount($userId)
    {
        $conn = Connection::getInstance();
        $query = "SELECT COUNT(*) as total FROM user_activity_logs WHERE user_id = ?";
        $row = $this->exQuery($conn, $query, "i", [$userId], true);
        Connection::release($conn);
        return (int)$row['total'];
    }
}
