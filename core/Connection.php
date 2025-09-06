<?php
namespace Mws\Core;

//use Exception;
use mysqli;
use mysqli_stmt;
use RuntimeException;

class Connection
{
    private static ?array $config = null;
    private static array $pool = [];
    private static int $activeConnections = 0;
    private static int $maxConnections = 100;
    private static ?string $mysqlVersion = null;

    /**
     * Initialize database configuration from environment variables.
     *
     * @throws RuntimeException If required configuration is missing or SSL files are invalid.
     */
    private static function initConfig(): void
    {
        if (self::$config !== null) {
            return;
        }

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
                'key'     => getenv('DB_SSL_KEY') ?: null,
            ],
        ];

        foreach (['host', 'username', 'database'] as $key) {
            if (empty(self::$config[$key])) {
                throw new RuntimeException("Missing required DB configuration: $key");
            }
        }

        // Validate SSL file paths if enabled
        if (self::$config['ssl']['enabled']) {
            foreach (['ca', 'cert', 'key'] as $key) {
                $path = self::$config['ssl'][$key];
                if ($path && (!file_exists($path) || !is_readable($path))) {
                    throw new RuntimeException("Invalid SSL $key file: $path does not exist or is not readable");
                }
            }
        }
    }

    /**
     * Detect MySQL version for version-specific optimizations.
     *
     * @param mysqli $conn The database connection.
     
    * @return string The MySQL version.
     */
    private static function detectMysqlVersion(mysqli $conn): string
    {
        if (self::$mysqlVersion === null) {
            $result = $conn->query('SELECT VERSION() AS version');
            if ($result && $row = $result->fetch_assoc()) {
                self::$mysqlVersion = $row['version'];
                $result->free();
            } else {
                self::$mysqlVersion = 'unknown';
            }
        }
        return self::$mysqlVersion;
    }

    /**
     * Get a connection from the pool or create a new one.
     *
     * @return mysqli The database connection.
     * @throws RuntimeException If connection pool is exhausted or connection fails.
     */
    public static function getInstance(): mysqli
    {
        self::initConfig();

        if ($conn = self::getPooled()) {
            return $conn;
        }

        if (self::$activeConnections < self::$maxConnections) {
            return self::createNew();
        }

        $attempts = 0;
        $maxAttempts = 5;
        $backoffMs = 100000; // 100ms
        while ($attempts < $maxAttempts) {
            if ($conn = self::getPooled()) {
                return $conn;
            }
            usleep($backoffMs * (2 ** $attempts));
            $attempts++;
        }

        throw new RuntimeException("Connection pool exhausted after $maxAttempts attempts");
    }

    /**
     * Retrieve an available connection from the pool.
     *
     * @return mysqli|null The connection if available, null otherwise.
     */
    private static function getPooled(): ?mysqli
    {
        foreach (self::$pool as $key => &$poolItem) {
            if (!$poolItem['inUse'] && $poolItem['connection']->ping()) {
                $poolItem['inUse'] = true;
                $poolItem['lastUsed'] = time();
                $poolItem['inTransaction'] = false;
                return $poolItem['connection'];
            }
        }
        return null;
    }

    /**
     * Create a new database connection with optimized settings and SSL support.
     *
     * @return mysqli The new connection.
     * @throws RuntimeException If connection or SSL setup fails.
     */
    private static function createNew(): mysqli
    {
        $conn = new mysqli();
        $config = self::$config;

        if ($config['ssl']['enabled']) {
            if (!$conn->ssl_set(
                $config['ssl']['key'],
                $config['ssl']['cert'],
                $config['ssl']['ca'],
                null,
                null
            )) {
                throw new RuntimeException('Failed to set SSL parameters');
            }
            // Enable server certificate verification
            $conn->options(MYSQLI_OPT_SSL_VERIFY_SERVER_CERT, true);
        }

        $conn->real_connect(
            'p:' . $config['host'], // Use persistent connections
            $config['username'],
            $config['password'],
            $config['database'],
            $config['port'],
            null,
            $config['ssl']['enabled'] ? MYSQLI_CLIENT_SSL : 0
        );

        if ($conn->connect_error) {
            error_log("Connection failed: {$conn->connect_error}");
            throw new RuntimeException("Connection failed: {$conn->connect_error}");
        }

        // Optimize connection settings
        $conn->set_charset('utf8mb4');
        $conn->query('SET SESSION sql_mode = "STRICT_TRANS_TABLES,NO_ZERO_DATE,NO_ZERO_IN_DATE,ERROR_FOR_DIVISION_BY_ZERO"');
        $conn->query('SET SESSION innodb_lock_wait_timeout = 5');
        $conn->query('SET SESSION wait_timeout = 300');
        $conn->query('SET SESSION interactive_timeout = 300');

        $poolKey = uniqid('conn_', true);
        self::$pool[$poolKey] = [
            'connection' => $conn,
            'inUse' => true,
            'inTransaction' => false,
            'created' => time(),
            'lastUsed' => time(),
            'key' => $poolKey,
            'statements' => [],
        ];

        self::$activeConnections++;
        self::detectMysqlVersion($conn);
        return $conn;
    }

    /**
     * Release a connection back to the pool.
     *
     * @param mysqli $conn The connection to release.
     */
    public static function release(mysqli $conn): void
    {
        foreach (self::$pool as $key => &$poolItem) {
            if ($poolItem['connection'] === $conn && $poolItem['inUse']) {
                if ($poolItem['inTransaction']) {
                    $conn->rollback();
                    error_log("Uncommitted transaction rolled back for connection $key");
                    $poolItem['inTransaction'] = false;
                }
                foreach ($poolItem['statements'] as $stmt) {
                    if ($stmt instanceof mysqli_stmt && !$stmt->errno) {
                        $stmt->reset(); // Reset for reuse
                    }
                }
                $poolItem['inUse'] = false;
                $poolItem['lastUsed'] = time();
                break;
            }
        }
    }

    /**
     * Mark a connection as in a transaction.
     *
     * @param mysqli $conn The connection.
     * @throws RuntimeException If the connection is already in a transaction.
     */
    public static function markTransactionStart(mysqli $conn): void
    {
        foreach (self::$pool as $key => &$poolItem) {
            if ($poolItem['connection'] === $conn) {
                if ($poolItem['inTransaction']) {
                    throw new RuntimeException('Nested transactions are not supported.');
                }
                $poolItem['inTransaction'] = true;
                break;
            }
        }
    }

    /**
     * Mark a connection as out of a transaction.
     *
     * @param mysqli $conn The connection.
     */
    public static function markTransactionEnd(mysqli $conn): void
    {
        foreach (self::$pool as $key => &$poolItem) {
            if ($poolItem['connection'] === $conn) {
                $poolItem['inTransaction'] = false;
                break;
            }
        }
    }

    /**
     * Cache a prepared statement for reuse.
     *
     * @param mysqli $conn The connection.
     * @param string $query The SQL query.
     * @param mysqli_stmt $stmt The prepared statement.
     */
    public static function cacheStatement(mysqli $conn, string $query, mysqli_stmt $stmt): void
    {
        $queryKey = md5($query);
        foreach (self::$pool as $key => &$poolItem) {
            if ($poolItem['connection'] === $conn) {
                if (!isset($poolItem['statements'][$queryKey]) || $poolItem['statements'][$queryKey]->errno) {
                    $poolItem['statements'][$queryKey] = $stmt;
                    if (count($poolItem['statements']) > 50) {
                        array_shift($poolItem['statements']);
                    }
                }
                break;
            }
        }
    }

    /**
     * Retrieve a cached prepared statement.
     *
     * @param mysqli $conn The connection.
     * @param string $query The SQL query.
     * @return mysqli_stmt|null The cached statement or null if not found.
     */
    public static function getCachedStatement(mysqli $conn, string $query): ?mysqli_stmt
    {
        $queryKey = md5($query);
        foreach (self::$pool as $key => &$poolItem) {
            if ($poolItem['connection'] === $conn) {
                $stmt = $poolItem['statements'][$queryKey] ?? null;
                if ($stmt instanceof mysqli_stmt && !$stmt->errno) {
                    $stmt->reset();
                    return $stmt;
                }
                unset($poolItem['statements'][$queryKey]);
                return null;
            }
        }
        return null;
    }

    /**
     * Clean up idle or dead connections from the pool.
     */
    public static function cleanupPool(): void
    {
        $now = time();
        $maxIdleTime = 60; // Reduced for faster cleanup

        foreach (self::$pool as $key => &$poolItem) {
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
     * Get statistics about the connection pool.
     *
     * @return array Pool statistics.
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
            'mysql_version' => self::$mysqlVersion ?? 'unknown',
            'ssl_enabled' => self::$config['ssl']['enabled'] ?? false,
        ];
    }

    /**
     * Close all connections during shutdown.
     */
    public static function shutdown(): void
    {
        foreach (self::$pool as $key => &$poolItem) {
            if ($poolItem['connection']->ping()) {
                if ($poolItem['inTransaction']) {
                    $poolItem['connection']->rollback();
                    error_log("Uncommitted transaction rolled back during shutdown for connection {$poolItem['key']}");
                }
                foreach ($poolItem['statements'] as $stmt) {
                    if ($stmt instanceof mysqli_stmt && !$stmt->errno) {
                        $stmt->close();
                    }
                }
                $poolItem['connection']->close();
            }
            unset(self::$pool[$key]);
        }
        self::$pool = [];
        self::$activeConnections = 0;
    }
}