<?php
namespace Mws\Core;

use Exception;
use mysqli;
use mysqli_stmt;

class Connection
{
    private static $pool = [];
    private static $activeConnections = 0;
    private static $maxConnections = 100;
    private static $config = null;
    private static $mysqlVersion = null;

    /**
     * Initialize database configuration once
     */
    private static function initConfig(): void
    {
        if (self::$config === null) {
            self::$config = [
                'host'     => getenv('DB_HOST') ?: null,
                'username' => getenv('DB_USER') ?: null,
                'password' => getenv('DB_PASS') ?: null,
                'database' => getenv('DB_NAME') ?: null,
                'port'     => (int)(getenv('DB_PORT') ?: 3306),
                'ssl'      => [
                    'enabled' => getenv('DB_SSL_ENABLED') === 'true',
                    'ca'      => getenv('DB_SSL_CA') ?: null,
                    'cert'    => getenv('DB_SSL_CERT') ?: null,
                    'key'     => getenv('DB_SSL_KEY') ?: null
                ]
            ];

            foreach (['host', 'username', 'database'] as $key) {
                if (empty(self::$config[$key])) {
                    throw new Exception("Missing required DB configuration: $key");
                }
            }
        }
    }

    /**
     * Detect MySQL version for version-specific optimizations
     */
    private static function detectMysqlVersion(mysqli $conn): string
    {
        if (self::$mysqlVersion === null) {
            $result = $conn->query("SELECT VERSION() as version");
            $row = $result->fetch_assoc();
            self::$mysqlVersion = $row['version'];
            $result->free();
        }
        return self::$mysqlVersion;
    }

    /**
     * Get a connection from the pool
     *
     * @return mysqli
     * @throws Exception
     */
    public static function getInstance(): mysqli
    {
        self::initConfig();

        $connection = self::getPooled();
        if ($connection) {
            return $connection;
        }

        if (self::$activeConnections < self::$maxConnections) {
            return self::createNew();
        }

        $attempts = 0;
        $maxAttempts = 5;
        while ($attempts < $maxAttempts) {
            $connection = self::getPooled();
            if ($connection) {
                return $connection;
            }
            usleep(100000 * (2 ** $attempts));
            $attempts++;
        }

        throw new Exception("Database connection pool exhausted after $maxAttempts attempts");
    }

    /**
     * Get a connection from the pool
     */
    private static function getPooled(): ?mysqli
    {
        foreach (self::$pool as $key => $poolItem) {
            if (!$poolItem['inUse'] && $poolItem['connection']->ping()) {
                self::$pool[$key]['inUse'] = true;
                self::$pool[$key]['lastUsed'] = time();
                self::$pool[$key]['inTransaction'] = false;
                return $poolItem['connection'];
            }
        }
        return null;
    }

    /**
     * Create a new optimized connection
     */
    private static function createNew(): mysqli
    {
        $config = self::$config;

        $conn = new mysqli();
        if ($config['ssl']['enabled']) {
            $conn->ssl_set(
                $config['ssl']['key'],
                $config['ssl']['cert'],
                $config['ssl']['ca'],
                null,
                null
            );
        }

        $conn->real_connect(
            $config['host'],
            $config['username'],
            $config['password'],
            $config['database'],
            $config['port'],
            null,
            $config['ssl']['enabled'] ? MYSQLI_CLIENT_SSL : 0
        );

        if ($conn->connect_error) {
            error_log("Database connection failed: " . $conn->connect_error);
            throw new Exception("Database connection failed: " . $conn->connect_error);
        }

        $conn->set_charset("utf8mb4");
        $conn->query("SET SESSION sql_mode = 'STRICT_TRANS_TABLES,NO_ZERO_DATE,NO_ZERO_IN_DATE,ERROR_FOR_DIVISION_BY_ZERO'");
        $conn->query("SET SESSION innodb_lock_wait_timeout = 5");
        $conn->query("SET SESSION wait_timeout = 300");
        $conn->query("SET SESSION interactive_timeout = 300");

        $poolKey = uniqid('conn_', true);
        self::$pool[$poolKey] = [
            'connection' => $conn,
            'inUse' => true,
            'inTransaction' => false,
            'created' => time(),
            'lastUsed' => time(),
            'key' => $poolKey,
            'statements' => []
        ];

        self::$activeConnections++;
        self::detectMysqlVersion($conn);
        return $conn;
    }

    /**
     * Release a connection back to the pool
     */
    public static function release(mysqli $conn): void
    {
        foreach (self::$pool as $key => $poolItem) {
            if ($poolItem['connection'] === $conn && $poolItem['inUse']) {
                if ($poolItem['inTransaction']) {
                    $conn->rollback();
                    error_log("Warning: Uncommitted transaction rolled back for connection $key");
                    self::$pool[$key]['inTransaction'] = false;
                }
                // Only close statements when connection is released
                foreach ($poolItem['statements'] as $stmt) {
                    if ($stmt instanceof mysqli_stmt && !$stmt->errno) {
                        $stmt->close();
                    }
                }
                self::$pool[$key]['statements'] = [];
                self::$pool[$key]['inUse'] = false;
                self::$pool[$key]['lastUsed'] = time();
                break;
            }
        }
    }

    /**
     * Mark a connection as in a transaction
     */
    public static function markTransactionStart(mysqli $conn): void
    {
        foreach (self::$pool as $key => $poolItem) {
            if ($poolItem['connection'] === $conn) {
                self::$pool[$key]['inTransaction'] = true;
                break;
            }
        }
    }

    /**
     * Mark a connection as out of a transaction
     */
    public static function markTransactionEnd(mysqli $conn): void
    {
        foreach (self::$pool as $key => $poolItem) {
            if ($poolItem['connection'] === $conn) {
                self::$pool[$key]['inTransaction'] = false;
                break;
            }
        }
    }

    /**
     * Cache a prepared statement
     */
    public static function cacheStatement(mysqli $conn, string $query, mysqli_stmt $stmt): void
    {
        foreach (self::$pool as $key => $poolItem) {
            if ($poolItem['connection'] === $conn) {
                $queryKey = md5($query);
                if (!isset($poolItem['statements'][$queryKey]) || $poolItem['statements'][$queryKey]->errno) {
                    self::$pool[$key]['statements'][$queryKey] = $stmt;
                }
                break;
            }
        }
    }

    /**
     * Get a cached prepared statement
     */
    public static function getCachedStatement(mysqli $conn, string $query): ?mysqli_stmt
    {
        foreach (self::$pool as $key => $poolItem) {
            if ($poolItem['connection'] === $conn) {
                $queryKey = md5($query);
                $stmt = $poolItem['statements'][$queryKey] ?? null;
                if ($stmt instanceof mysqli_stmt && !$stmt->errno) {
                    return $stmt;
                }
                // Remove invalid or closed statement
                unset(self::$pool[$key]['statements'][$queryKey]);
                return null;
            }
        }
        return null;
    }

    /**
     * Clean up old/unused connections
     */
    public static function cleanupPool(): void
    {
        $now = time();
        $maxIdleTime = 120;

        foreach (self::$pool as $key => $poolItem) {
            if (!$poolItem['inUse'] && ($now - $poolItem['lastUsed']) > $maxIdleTime) {
                foreach ($poolItem['statements'] as $stmt) {
                    if ($stmt instanceof mysqli_stmt && !$stmt->errno) {
                        $stmt->close();
                    }
                }
                $poolItem['connection']->close();
                unset(self::$pool[$key]);
                self::$activeConnections--;
            } elseif (!$poolItem['connection']->ping()) {
                foreach ($poolItem['statements'] as $stmt) {
                    if ($stmt instanceof mysqli_stmt && !$stmt->errno) {
                        $stmt->close();
                    }
                }
                unset(self::$pool[$key]);
                self::$activeConnections--;
            }
        }
    }

    /**
     * Get pool statistics
     */
    public static function getPoolStats(): array
    {
        $inUse = 0;
        $available = 0;
        $inTransaction = 0;
        $cachedStatements = 0;

        foreach (self::$pool as $poolItem) {
            if ($poolItem['inUse']) {
                $inUse++;
                if ($poolItem['inTransaction']) {
                    $inTransaction++;
                }
            } else {
                $available++;
            }
            $cachedStatements += count($poolItem['statements']);
        }

        return [
            'total_connections' => self::$activeConnections,
            'in_use' => $inUse,
            'in_transaction' => $inTransaction,
            'available' => $available,
            'cached_statements' => $cachedStatements,
            'max_connections' => self::$maxConnections,
            'mysql_version' => self::$mysqlVersion ?? 'unknown'
        ];
    }

    /**
     * Graceful shutdown - close all connections
     */
    public static function shutdown(): void
    {
        foreach (self::$pool as $poolItem) {
            if ($poolItem['connection']->ping()) {
                if ($poolItem['inTransaction']) {
                    $poolItem['connection']->rollback();
                    error_log("Warning: Uncommitted transaction rolled back during shutdown for connection {$poolItem['key']}");
                }
                foreach ($poolItem['statements'] as $stmt) {
                    if ($stmt instanceof mysqli_stmt && !$stmt->errno) {
                        $stmt->close();
                    }
                }
                $poolItem['connection']->close();
            }
        }

        self::$pool = [];
        self::$activeConnections = 0;
    }
}