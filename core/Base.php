<?php
namespace Mws\Core;

use mysqli;
use Exception;
use InvalidArgumentException;
use RuntimeException;

abstract class Base
{
      /**
     * Execute a prepared query with parameters.
     *
     * @param mysqli $conn The database connection.
     * @param string $query The SQL query.
     * @param string $types The parameter types (e.g., 'is' for integer and string).
     * @param array $params The query parameters.
     * @param bool $single Whether to fetch a single row.
     * @return array|null|bool The query result (array for SELECT, bool for others).
     * @throws RuntimeException If the query fails.
     */
    protected function exQuery(mysqli $conn, string $query, string $types = '', array $params = [], bool $single = false): array|bool|null
    {
        if ($conn->connect_error) {
            throw new RuntimeException('Database connection failed: ' . $conn->connect_error);
        }

        $stmt = Connection::getCachedStatement($conn, $query) ?? $conn->prepare($query);
        if (!$stmt) {
            throw new RuntimeException('Failed to prepare statement: ' . $conn->error);
        }

        Connection::cacheStatement($conn, $query, $stmt);

        if ($types && $params) {
            if (count($params) !== strlen($types)) {
                throw new RuntimeException('Number of parameters does not match types.');
            }
            $stmt->bind_param($types, ...$params);
        }

        if (!$stmt->execute()) {
            throw new RuntimeException('Query execution failed: ' . $stmt->error);
        }

        if ($stmt->result_metadata()) {
            $result = $stmt->get_result();
            if (!$result) {
                throw new RuntimeException('Failed to get query result: ' . $stmt->error);
            }

            $data = $single ? $result->fetch_assoc() : $result->fetch_all(MYSQLI_ASSOC);
            $result->free();
            return $data;
        }

        return $stmt->affected_rows > 0;
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
    protected function exTransaction(callable|array $task): mixed
    {
        $conn = Connection::getInstance();

        try {
            Connection::markTransactionStart($conn);

            if (!$conn->begin_transaction()) {
                throw new RuntimeException('Failed to begin transaction: ' . $conn->error);
            }

            $result = null;

            if (is_callable($task)) {
                $result = $task($conn);
            } elseif (is_array($task)) {
                if (empty($task)) {
                    throw new InvalidArgumentException('Batch query array cannot be empty.');
                }

                foreach ($task as $index => $query) {
                    if (!is_array($query) || !isset($query['sql'], $query['types'], $query['params'])) {
                        throw new InvalidArgumentException("Invalid query format at index $index: 'sql', 'types', and 'params' are required.");
                    }
                    if (!is_string($query['sql']) || !is_string($query['types']) || !is_array($query['params'])) {
                        throw new InvalidArgumentException("Invalid query format at index $index: 'sql' and 'types' must be strings, 'params' must be an array.");
                    }
                    $this->exQuery($conn, $query['sql'], $query['types'], $query['params']);
                }
                $result = true;
            } else {
                throw new InvalidArgumentException('Task must be a callable or an array of queries.');
            }

            if (!$conn->commit()) {
                throw new RuntimeException('Failed to commit transaction: ' . $conn->error);
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
    protected function mapFields(array $data, array $allowedFields, array $fieldTypes): array 
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
