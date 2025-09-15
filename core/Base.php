<?php
namespace Svm\Core;

use Svm\Core\Connection;
use Svm\Helpers\Utils;
use Doctrine\DBAL\ParameterType;
use RuntimeException;
use InvalidArgumentException;
use DateTimeInterface;
use DateTime;
use Throwable;

abstract class Base
{
    /**
     * Execute a SELECT query and return multiple rows
     */
    public static function select(string $sql, array $params = [], array $types = []): array
    {
        return self::executeQuery(
            fn() => Connection::getInstance()->executeQuery($sql, $params, $types)->fetchAllAssociative() ?: [],
            $sql
        );
    }

    /**
     * Execute a SELECT query and return a single row
     */
    public static function selectOne(string $sql, array $params = [], array $types = []): ?array
    {
        return self::executeQuery(
            fn() => Connection::getInstance()->fetchAssociative($sql, $params, $types) ?: null,
            $sql
        );
    }

    /**
     * Execute an INSERT statement
     */
    protected function insert(string $sql, array $params = [], array $types = []): int
    {
        return self::executeQuery(
            fn() => Connection::getInstance()->executeStatement($sql, $params, $types),
            $sql
        );
    }

    /**
     * Execute an UPDATE statement
     */
    protected function update(string $sql, array $params = [], array $types = []): int
    {
        return self::executeQuery(
            fn() => Connection::getInstance()->executeStatement($sql, $params, $types),
            $sql
        );
    }

    /**
     * Execute a DELETE statement
     */
    protected function delete(string $sql, array $params = [], array $types = []): int
    {
        return self::executeQuery(
            fn() => Connection::getInstance()->executeStatement($sql, $params, $types),
            $sql
        );
    }

    /**
     * Common query execution with error handling
     */
    private static function executeQuery(callable $query)
    {
        try {
            return $query();
        } catch (Throwable $e) {
            throw new RuntimeException("Query failed: {$e->getMessage()}", 0, $e);
        }
    }

    /**
     * Execute a transaction
     */
    public static function transaction(callable $callback, bool $useSavepoints = true)
    {
        $conn = Connection::getInstance();
        $conn->beginTransaction();

        try {
            $result = $callback($conn);
            $conn->commit();
            return $result;
        } catch (Throwable $e) {
            if ($useSavepoints && $conn->isTransactionActive()) {
                $conn->rollBack();
            }
            throw $e;
        }
    }

   /**
     * Prepare data for insert/update dynamically for any model.
     *
     * @param object $model Any model object
     * @param array $data Input data
     * @return array ['columns' => [], 'placeholders' => [], 'params' => [], 'types' => []]
     */
    protected function bind(object|array $data): array
    {
        // If object, convert it to array of public properties
        if (is_object($data)) {
            $data = get_object_vars($data);
        }

        $columns = [];
        $placeholders = [];
        $set = [];
        $params = [];
        $types = [];

        foreach ($data as $field => $value) {
            if ($value === null) continue;

            $columns[]      = $field;
            $placeholders[] = '?';
            $set[]          = "$field = ?";

            if ($value instanceof DateTime) {
                $params[] = $value->format('Y-m-d H:i:s');
                $types[]  = ParameterType::STRING;
                continue;
            }

            $params[] = $value;
            $types[] = match (gettype($value)) {
                'integer' => ParameterType::INTEGER,
                'boolean' => ParameterType::BOOLEAN,
                'NULL'    => ParameterType::STRING,
                default   => ParameterType::STRING,
            };
        }

        if (empty($columns)) {
            throw new InvalidArgumentException("No valid fields provided for DB operation.");
        }

        return [
            'c'  => $columns,
            'ph' => $placeholders,
            's'  => $set,
            'p'  => $params,
            't'  => $types
        ];
    }


    /**
     * Log a user action in user_activity_logs
     */
    protected function logUserAction($conn, int $userId, string $action, array $details = []): void
    {
        $statusId = $conn->fetchOne(
            "SELECT status_id FROM statuses WHERE status_code = :code LIMIT 1",
            ['code' => $action]
        );

        if (!$statusId) {
            throw new RuntimeException("Invalid action code: {$action}");
        }

        $conn->insert('audit_logs', [
            'user_id' => $userId,
            'status_id' => $statusId,
            'ip_address' => Utils::getClientIp(),
            'user_agent' => Utils::getUserAgent(),
            'action_timestamp' => date('Y-m-d H:i:s'),
            'details' => json_encode($details, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE),
        ]);
    }

    /**
     * Build pagination metadata
     */
    protected function buildPagination($totalRecords, $currentPage, $limit): array
    {
        $totalPages = ceil($totalRecords / $limit);
        return [
            'current_page' => $currentPage,
            'per_page' => $limit,
            'total_records' => $totalRecords,
            'total_pages' => $totalPages,
            'has_previous' => $currentPage > 1,
            'has_next' => $currentPage < $totalPages,
            'from' => (($currentPage - 1) * $limit) + 1,
            'to' => min($currentPage * $limit, $totalRecords),
        ];
    }

    /**
     * Handle database errors by code
     */
    public static function handleDBError(RuntimeException $e): ?array
    {
        $msg = $e->getMessage();

        return match (true) {
            str_contains($msg, '1062') => [
                'message' => str_contains($msg, 'username') ? 'Username is not available'
                    : (str_contains($msg, 'email') ? 'Email is already in use' : 'Duplicate entry'),
                'code' => RespCode::CONFLICT,
            ],
            str_contains($msg, '1451') => [
                'message' => 'Cannot delete record; it is referenced elsewhere',
                'code' => RespCode::CONFLICT,
            ],
            str_contains($msg, '1048') => [
                'message' => 'A required field was not provided',
                'code' => RespCode::BAD_REQUEST,
            ],
            default => null,
        };
    }

    /**
     * Normalize payload with system fields
     */
    public static function normalize(array $payload, array $systemFields = [], bool $forceOverride = true): array
    {
        $data = $payload['data'] ?? [];

        foreach ($systemFields as $key => $default) {
            if ($forceOverride || !array_key_exists($key, $data)) {
                $data[$key] = $payload[$key] ?? $default;
            }
        }

        return $data;
    }
}