<?php
namespace Svm\Repository;

use Svm\Core\Base;
use Svm\Models\Users;
use Svm\Helpers\Utils;
use Doctrine\DBAL\ParameterType;

class UserRepo extends Base // Extend to Database
{
    public function findAll(int $page = 1, int $limit = 10): array
    {
        $offset = ($page - 1) * $limit;

        $sql = "SELECT user_id, username, email,
                       CONCAT(first_name, ' ', last_name) AS full_name,
                       last_ip_address, last_login, is_online, is_active, created_at
                FROM users
                WHERE deleted_at IS NULL
                ORDER BY user_id DESC
                LIMIT ? OFFSET ?";

        return [
            'success' => true,
            'data' => self::select($sql, [$limit, $offset], [ParameterType::INTEGER, ParameterType::INTEGER]),
            'pagination' => $this->buildPagination($this->getTotalCount(), $page, $limit),
            'error' => null
        ];
    }

    public function findById(int $id): ?array //can return null
    {
        $sql = "SELECT user_id, username, email, first_name, last_name,
                    last_ip_address, last_login, last_logout, failed_attempts,
                    lock_until, is_two_factor, is_online, is_approved,
                    is_active, created_at, updated_at
                FROM users
                WHERE user_id = ? AND deleted_at IS NULL
                LIMIT 1";

        return self::selectOne($sql, [$id], [ParameterType::INTEGER]);
    }

    public function findByUsername(string $username): ?array //can return null
    {
        $sql = "SELECT user_id, username, password_hash, failed_attempts,
                    lock_until, is_two_factor, is_online, is_approved, is_active, deleted_at
                FROM users
                WHERE username = ?
                LIMIT 1";

        return self::selectOne($sql, [$username], [ParameterType::STRING]);
    }

    public function findByEmail(string $email): ?array //can return null
    {
        $sql = "SELECT user_id, email, is_two_factor
                FROM users
                WHERE email = ? AND deleted_at IS NULL
                LIMIT 1";

        return self::selectOne($sql, [$email], [ParameterType::STRING]) ?: null;
    }

    public function addUser(array $data): bool
    {
        return $this->transaction(function ($conn) use ($data): bool {

            $user = new Users($data);
            
            //Debug
            //print_r($user);

            // Use helper to prepare SQL fields dynamically
            $bind = $this->bind($user);
            if (empty($bind['c'])) return false;

            // Add created_at manually
            // $bind['c'][] = 'created_at';
            // $bind['ph'][] = 'NOW()';

            // Build the INSERT statement
            $stmt = sprintf(
                "INSERT INTO users (%s) VALUES (%s)",
                implode(', ', $bind['c']),
                implode(', ', $bind['ph'])
            );

            // Execute
            $this->insert($stmt, $bind['p'], $bind['t']);

            // Log user creation
            $this->logUserAction(
                $conn,
                $conn->lastInsertId(),
                'ACCOUNT_CREATED',
                ['action' => 'User account created', 'created_by' => $data['created_by'] ?? null]
            );

            return true;
        });
    }


    public function updateUser(int $id, array $data): bool
    {
        return $this->transaction(function ($conn) use ($id, $data): bool {

            $user = new Users($data);
            
            // Use helper to prepare SQL fields dynamically
            $bind = $this->bind($user);
            if (empty($bind['s'])) return false;

            // Add updated_at manually
            $bind['s'][] = 'updated_at = NOW()';
            // Add WHERE clause parameters
            $bind['p'][] = $id;
            $bind['t'][]  = ParameterType::INTEGER;

            // Build the UPDATE statement
            $stmt = "UPDATE users SET " . implode(', ', $bind['s']) . 
                    "WHERE user_id = ? AND deleted_at IS NULL";

            // Execute
            if (!$this->update($stmt, $bind['p'], $bind['t']) > 0) {
                return false;
            }

            // Determine log action
            $logAction = match (true) {
                isset($data['password_hash']) => 'PASSWORD_CHANGE',
                isset($data['is_two_factor']) => $data['is_two_factor'] ? '2FA_ENABLED' : '2FA_DISABLED',
                isset($data['lock_until'])    => $data['lock_until']    ? 'ACCOUNT_LOCKED' : 'ACCOUNT_UNLOCKED',
                default                       => 'ACCOUNT_UPDATED',
            };

            $this->logUserAction(
                $conn,
                $id,
                $logAction,
                ['action' => 'User account updated', 'updated_by' => $data['updated_by'] ?? null]
            );

            return true;
        });
    }


    public function deleteUser(int $id): bool
    {
        return $this->transaction(function ($conn) use ($id): bool {

            $stmt = "UPDATE users SET deleted_at = NOW() WHERE user_id = ? AND deleted_at IS NULL";

            if(!$this->update($stmt, [$id], [ParameterType::INTEGER]) > 0) return false;

            $this->logUserAction($conn, $id, 'ACCOUNT_DELETED', ['action' => 'User account soft-deleted', 'deleted_by'=> '']);
            
            return true;
        });
    }

    public function undeleteUser(int $id): bool
    {
        return $this->transaction(function ($conn) use ($id): bool {

            $stmt = "UPDATE users SET deleted_at = NULL WHERE user_id = ? AND deleted_at IS NOT NULL";

            if(!$this->update($stmt, [$id], [ParameterType::INTEGER]) > 0) return false;

            $this->logUserAction($conn, $id, 'ACCOUNT_UNDELETED', ['action' => 'User account restored']);

            return true;
        });
    }

    // ----------------------
    // LOGIN ATTEMPTS
    // ----------------------
    public function updateLoginAttempts(int $userId, int $failedAttempts, ?string $lockUntil = null): bool
    {
        return $this->transaction(function ($conn) use ($userId, $failedAttempts, $lockUntil): bool 
        {

            $stmt = "UPDATE users
                     SET failed_attempts = ?, lock_until = ?, last_ip_address = ?
                     WHERE user_id = ? AND deleted_at IS NULL";

            $params = [$failedAttempts, $lockUntil, Utils::getClientIp(), $userId];
            $types  = [ParameterType::INTEGER, ParameterType::STRING, ParameterType::STRING, ParameterType::INTEGER];

            if (!$this->update($stmt, $params, $types)) return false;

            $action  = $lockUntil ? 'ACCOUNT_LOCKED' : 'LOGIN_ATTEMPT';
            $details = $lockUntil ? ['reason' => 'Too many failed attempts'] : ['attempt_count' => $failedAttempts];

            $this->logUserAction($conn, $userId, $action, $details);

            return true; // true
        });
    }


    public function resetLoginAttempts(int $userId): bool
    {
        return $this->transaction(function ($conn) use ($userId): bool 
        {
            // Update user status
            $stmt = "UPDATE users SET failed_attempts = 0, lock_until = NULL WHERE user_id = ? AND deleted_at IS NULL";
            
            if (!$this->update($stmt, [$userId], [ParameterType::INTEGER]) > 0) return false;

            // Log Action
            $this->logUserAction($conn, $userId, 'ACCOUNT_UNLOCKED', ['action' => 'Login attempts reset']);

            return true; // true
        });
    }

    public function storeTokens(int $userId, string $jwt, string $refreshToken, int $expire, int $refreshExpire): bool
    {
        return $this->transaction(function ($conn) use ($userId, $jwt, $refreshToken, $expire, $refreshExpire): bool 
        {        
            $deviceInfo = Utils::getDeviceInfo();

            // Insert Token
            $stmt = "INSERT INTO user_tokens (user_id, jwt_token, refresh_token, token_expiry, refresh_expiry, device_info)
                     VALUES (?, ?, ?, FROM_UNIXTIME(?), FROM_UNIXTIME(?), ?)";
            $params = [$userId, $jwt, $refreshToken, $expire, $refreshExpire, $deviceInfo];
            $types  = [ParameterType::INTEGER, ParameterType::STRING, ParameterType::STRING,
                       ParameterType::INTEGER, ParameterType::INTEGER, ParameterType::STRING];    
            $this->insert($stmt, $params, $types);

            // Update User status
            $updateStmt = "UPDATE users SET last_login = NOW(), is_online = 1, last_ip_address = ? WHERE user_id = ? AND deleted_at IS NULL";
            if(!$this->update($updateStmt, [Utils::getClientIp(), $userId], [ParameterType::STRING, ParameterType::INTEGER]) > 0)  return false;

            // Log Action
            $this->logUserAction($conn, $userId, 'LOGIN', ['action' => 'User logged in', 'device' => $deviceInfo]);

            return true;
        });
    }

    public function clearTokens(int $userId): bool
    {
        return $this->transaction(function ($conn) use ($userId): bool {
            
            $user = $this->selectOne("SELECT is_online FROM users WHERE user_id = ? AND deleted_at IS NULL LIMIT 1", [$userId]);
            // Return false if user not found or not online
            if (!$user || $user['is_online'] !== 1) return false;

            // Delete tokens; return false if none deleted
            $deleteStmt = "DELETE FROM user_tokens WHERE user_id = ?";
            if(!$this->delete($deleteStmt, [$userId], [ParameterType::INTEGER]) > 0) return false;

            // Update user status
            $updateStmt = "UPDATE users SET is_online = 0, last_logout = NOW(), last_ip_address = ? WHERE user_id = ? AND deleted_at IS NULL";
            if(!$this->update($updateStmt,[Utils::getClientIp(), $userId], [ParameterType::STRING, ParameterType::INTEGER]) > 0) return false;

            // Log action
            $this->logUserAction($conn, $userId, 'LOGOUT', ['action' => 'User logged out', 'device' => Utils::getDeviceInfo()]);

            return true;
        });
    }

    public function findRefreshToken(string $refreshToken): ? array
    {
        $stmt = "SELECT ut.user_id, u.username, ut.refresh_token, ut.jwt_token,
                    ut.token_expiry, ut.refresh_expiry, ut.device_info
                 FROM user_tokens ut
                 JOIN users u ON u.user_id = ut.user_id
                 WHERE ut.refresh_token = ?
                 LIMIT 1";

        return self::selectOne($stmt, [$refreshToken], [ParameterType::STRING]);
    }

    public function updateAccessToken(
        int $userId,
        string $jwt,
        int $expire,
        string $refreshToken,
        int $refreshExpire
    ): bool
    {
        $stmt = "UPDATE user_tokens
                 SET jwt_token = ?, token_expiry = FROM_UNIXTIME(?),
                     refresh_token = ?, refresh_expiry = FROM_UNIXTIME(?)
                 WHERE user_id = ? AND device_info = ?";

        $params = [$jwt, $expire, $refreshToken, $refreshExpire, $userId, Utils::getDeviceInfo()];
        $types  = [ParameterType::STRING, ParameterType::INTEGER,
                   ParameterType::STRING, ParameterType::INTEGER,
                   ParameterType::INTEGER, ParameterType::STRING];

        return  $this->update($stmt, $params, $types) > 0; // affected rows
    }

    // ----------------------
    // ACTIVITY LOGGING
    // ----------------------
    public function findUserActivity(int $userId, int $limit = 50, int $page = 1): array
    {
        $offset = ($page - 1) * $limit;

        $stmt = "SELECT l.log_id, l.user_id, s.status_code, s.display_name AS action_name,
                    l.ip_address, l.user_agent, l.action_timestamp, l.details
                 FROM user_activity_logs l
                 JOIN statuses s ON l.status_id = s.status_id
                 WHERE l.user_id = ?
                 ORDER BY l.action_timestamp DESC
                 LIMIT {$limit} OFFSET {$offset}";

        // Fetch all logs
        $logs = $this->select($stmt, [$userId]);

        // Get total for pagination
        $total = $this->getActivityTotalCount($userId);
        $pagination = $this->buildPagination($total, $page, $limit);

        return ['data' => $logs, 'pagination' => $pagination];
    }

    // ----------------------
    // PAGINATION HELPERS
    // ----------------------
    protected function getTotalCount(): int
    {
        $sql = "SELECT COUNT(*) AS total FROM users WHERE deleted_at IS NULL";
        $result = self::selectOne($sql);
        return ($result['total'] ?? 0);
    }

    public function getActivityTotalCount($userId): int
    {
        $stmt = "SELECT COUNT(*) as total FROM user_activity_logs WHERE user_id = ?";
        $result = $this->select($stmt, [$userId]);
        return ($result['total'] ?? 0);
    }
    
}
