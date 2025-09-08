<?php
namespace Mws\Core;

use mysqli;
use Exception;
use InvalidArgumentException;
use RuntimeException;
use Mws\Helpers\Utils;

abstract class Base
{
    /**
     * Executes a SQL query with prepared statements and returns a consistent result.
     *
     * @param mysqli $conn Database connection
     * @param string $query SQL query to execute
     * @param string $types Parameter types for binding (e.g., 'sii')
     * @param array $params Parameters to bind
     * @return array Returns ['success' => bool, 'data' => array|null, 'affected_rows' => int, 'insert_id' => int]
     * @throws InvalidArgumentException If parameters or types are invalid
     * @throws RuntimeException If database operations fail
     *
     * Note: For single-row SELECT queries, include LIMIT 1 to optimize memory usage and clarify intent. Validate result count in the calling method.
     */
    protected function runQuery(mysqli $conn, string $query, string $types = '', array $params = []): array
    {
        if ($conn->connect_error) {
            throw new RuntimeException("Database connection failed: {$conn->connect_error}");
        }

        // Validate params
        if ($types && count($params) !== strlen($types)) {
            throw new InvalidArgumentException(
                "Parameter count (" . count($params) . ") does not match types (" . strlen($types) . ")."
            );
        }

        $stmt = $conn->prepare($query);
        if (!$stmt) {
            throw new RuntimeException("Failed to prepare statement: {$conn->error} (Query: " . substr($query, 0, 120) . ")");
        }

        try {
            if ($types && $params) {
                $stmt->bind_param($types, ...$params);
            }

            if (!$stmt->execute()) {
                throw new RuntimeException("Query execution failed: {$stmt->error} (Query: " . substr($query, 0, 120) . ")");
            }

            $result = [
                'success' => true,
                'data' => null,
                'affected_rows' => $stmt->affected_rows,
                'insert_id' => $stmt->insert_id
            ];

            // SELECT queries return data
            if ($stmt->result_metadata()) {
                $rs = $stmt->get_result();
                if (!$rs) {
                    throw new RuntimeException("Failed to fetch result: {$stmt->error}");
                }

                $result['data'] = $rs->fetch_all(MYSQLI_ASSOC) ?: [];
                $rs->free();
            }

            return $result;

        } finally {
            $stmt->close(); // ✅ clean lifecycle
        }
    }

     /**
     * Execute a transaction with a callback or a batch of queries.
     *
     * @param callable|array $task Either a callback function that accepts a mysqli connection or an array of query arrays.
     * Each query array must contain 'sql', 'types', and 'params' keys.
     * @return mixed The result of the callback or true for successful batch queries.
     * @throws InvalidArgumentException If the task is invalid or query format is incorrect.
     * @throws RuntimeException If the transaction fails to begin, commit, or execute.
     */
    protected function transact(callable|array $task): mixed
    {
        $conn = Connection::getInstance();

        try {
            Connection::markTransactionStart($conn);
            if (!$conn->begin_transaction()) {
                throw new RuntimeException('Database failed to begin transaction: ' . $conn->error);
            }

            $result = null;

            if (is_callable($task)) {
                $result = $task($conn);
            } elseif (is_array($task)) {
                if (empty($task)) {
                    throw new InvalidArgumentException('Batch query array cannot be empty.');
                }
                foreach ($task as $index => $query) {
                    if (!isset($query['sql'], $query['types'], $query['params'])) {
                        throw new InvalidArgumentException("Invalid query format at index $index: 'sql', 'types', and 'params' are required.");
                    }
                    $this->runQuery($conn, $query['sql'], $query['types'], $query['params']);
                }
                $result = true;
            } else {
                throw new InvalidArgumentException('Task must be a callable or an array of queries.');
            }

            if (!$conn->commit()) {
                throw new RuntimeException('Database failed to commit transaction: ' . $conn->error);
            }

            return $result;
        } catch (Exception $e) {
            $conn->rollback();
            throw $e;
        } finally {
            Connection::markTransactionEnd($conn);
            Connection::release($conn);
        }
    }
    
    /**
     * Build SQL parts (fields, placeholders, params, types) from given data.
     *
     * @param array $data          Incoming user data (from request, etc.)
     * @param array $allowedFields Fields this model allows (keys must exist in FIELD_TYPES)
     * @param array $fieldTypes    Field => type mapping (e.g. ['username' => 's'])
     */
    protected function prepareSqlFields(array $data, array $allowedFields, array $fieldTypes): array 
    {
        $fields = [];
        $placeholders = [];
        $set = [];
        $params = [];
        $types = [];

        foreach ($allowedFields as $field) {
            if (array_key_exists($field, $data)) {
                if (!isset($fieldTypes[$field])) {
                    throw new InvalidArgumentException("Missing type mapping for field '$field'.");
                }

                $fields[]       = $field;
                $placeholders[] = '?';
                $set[]          = "$field = ?";
                $params[]       = $data[$field];
                $types[]        = $fieldTypes[$field];
            }
        }

        if (empty($fields)) {
            throw new InvalidArgumentException("No valid fields provided.");
        }

        return [
            'fields'       => $fields,              // INSERT fields
            'placeholders' => $placeholders,        // INSERT values
            'set'          => $set,                 // UPDATE
            'params'       => $params,
            'types'        => implode('', $types),
        ];
    }

    /**
     * Logs a user action into the activity logs.
     *
     * @param mysqli $conn Active database connection (within transaction).
     * @param int    $userId User ID performing the action.
     * @param string $actionCode Status code representing the action.
     * @param array|null $details Optional details to log as JSON.
     * @return array Returns ['success' => bool, 'id' => int|null]
     */
    protected function logUserAction(mysqli $conn, int $userId, string $actionCode, array $details = null): array
    {
        // No need to call transact because its already part of a transact when used
        // Get status_id for the action
        $stmt = "SELECT status_id
                 FROM statuses
                 WHERE status_code = ? 
                 AND category = 'USER_ACTION' 
                 AND is_active = 1
                 LIMIT 1";

        $result = $this->runQuery($conn, $stmt, "s", [$actionCode]);
        $status = $result['data'][0] ?? null;

        if (!$status) {
            return [
                'success' => false,
                'id'      => null,
                'error'   => "Invalid action code '$actionCode' for user_id $userId"
            ];
        }

        // Insert into user_activity_logs
        $detailsJson = $details ? json_encode($details, JSON_UNESCAPED_SLASHES) : null;

        $insert = "INSERT INTO user_activity_logs (user_id, status_id, ip_address, user_agent, details)
                   VALUES (?, ?, ?, ?, ?)";

        $insertResult = $this->runQuery($conn, $insert, "iisss", [$userId, $status['status_id'], Utils::getClientIp(), Utils::getUserAgent(), $detailsJson]);

        return [
            'success' => $insertResult['success'],
            'id'      => $insertResult['insert_id'] ?? null
        ];
    }

    /**
     * Build pagination metadata.
     */
    protected function buildPagination($totalRecords, $currentPage, $limit)
    {
        $totalPages = ceil($totalRecords / $limit);
        return [
            'current_page'  => $currentPage,
            'per_page'      => $limit,
            'total_records' => $totalRecords,
            'total_pages'   => $totalPages,
            'has_previous'  => $currentPage > 1,
            'has_next'      => $currentPage < $totalPages,
            'from'          => (($currentPage - 1) * $limit) + 1,
            'to'            => min($currentPage * $limit, $totalRecords)
        ];
    }
    
}
