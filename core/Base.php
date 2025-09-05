<?php
namespace Mws\Core;

use Exception;

abstract class Base
{
   /**
     * Execute query with optional binding and return results.
     */
    protected function exQuery($conn, $query, $types = "", $params = [], $single = false)
    {
        $stmt = Connection::getCachedStatement($conn, $query) ?? $conn->prepare($query);
        if (!$stmt) {
            throw new Exception("Failed to prepare statement: " . $conn->error);
        }
        Connection::cacheStatement($conn, $query, $stmt);

        if ($types && $params) {
            // Copy params into variables so bind_param can take references
            $bindParams = [];
            foreach ($params as $key => $value) {
                $bindParams[$key] = $value;
            }

            // Build references dynamically
            $refs = [];
            foreach ($bindParams as $key => &$val) {
                $refs[$key] = &$val;
            }

            array_unshift($refs, $types);
            call_user_func_array([$stmt, 'bind_param'], $refs);
        }

        $stmt->execute();
        $result = $stmt->get_result();

        if ($result) {
            $data = $single ? $result->fetch_assoc() : $result->fetch_all(MYSQLI_ASSOC);
            $result->free();
            return $data;
        }

        return $stmt->affected_rows > 0;
    }

    /**
     * Execute a transaction safely.
     * Can take a callback OR an array of queries for batch execution.
     */
    protected function exTransaction($task)
    {
        $conn = Connection::getInstance();
        try {
            Connection::markTransactionStart($conn);
            if (!$conn->begin_transaction()) {
                throw new Exception("Failed to begin transaction");
            }

            $result = null;

            // If task is a callback
            if (is_callable($task)) {
                $result = $task($conn);
            }
            // If task is an array of queries
            elseif (is_array($task)) {
                foreach ($task as $q) {
                    if (!isset($q['sql'], $q['types'], $q['params'])) {
                        throw new Exception("Invalid query format in batch");
                    }
                    $this->exQuery($conn, $q['sql'], $q['types'], $q['params']);
                }
                $result = true;
            }

            if (!$conn->commit()) {
                throw new Exception("Failed to commit transaction");
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
