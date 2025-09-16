<?php
namespace Svm\Core;

use Doctrine\DBAL\DriverManager;
use Doctrine\DBAL\Connection as DBALConnection;
use Doctrine\DBAL\Connections\PrimaryReadReplicaConnection;
use Doctrine\DBAL\Exception;
use Doctrine\DBAL\Exception\ConnectionException;
use Doctrine\DBAL\Query\QueryBuilder;
use Psr\Log\LoggerInterface;
use Psr\Log\NullLogger;
use RuntimeException;

class Connection
{
    private static ?DBALConnection $conn = null;
    private static ?string $mysqlVersion = null;
    private static ?LoggerInterface $logger = null;

    public function setLogger(LoggerInterface $logger): void
    {
        self::$logger = $logger;
    }

    private static function init(): void
    {
        if (self::$conn !== null) {
            return;
        }

        if (self::$logger === null) {
            self::$logger = new NullLogger();
        }

        $required = ['DB_NAME', 'DB_USER', 'DB_PASS', 'DB_HOST'];
        foreach ($required as $env) {
            if (empty(getenv($env))) {
                throw new RuntimeException("Missing required env variable: {$env}");
            }
        }

        $config = [
            'dbname'   => getenv('DB_NAME'),
            'user'     => getenv('DB_USER'),
            'password' => getenv('DB_PASS'),
            'host'     => getenv('DB_HOST'),
            'port'     => getenv('DB_PORT') ?: 3306,
            'driver'   => 'pdo_mysql',
            'charset'  => 'utf8mb4',
            'driverOptions' => [
                \PDO::ATTR_ERRMODE            => \PDO::ERRMODE_EXCEPTION,
                \PDO::ATTR_DEFAULT_FETCH_MODE => \PDO::FETCH_ASSOC,
                \PDO::ATTR_EMULATE_PREPARES   => false,
            ],
        ];

        if ($serverVersion = getenv('DB_SERVER_VERSION')) {
            $config['serverVersion'] = $serverVersion;
        }

        if (getenv('DB_PERSISTENT') === 'true') {
            $config['persistent'] = true;
        }

        // SSL Support
        if (getenv('DB_SSL_ENABLED') === 'true') {
            foreach (['DB_SSL_CA' => \PDO::MYSQL_ATTR_SSL_CA,
                      'DB_SSL_CERT' => \PDO::MYSQL_ATTR_SSL_CERT,
                      'DB_SSL_KEY' => \PDO::MYSQL_ATTR_SSL_KEY] as $env => $opt) {
                $path = getenv($env);
                if ($path && (!file_exists($path) || !is_readable($path))) {
                    throw new RuntimeException("Invalid SSL file: {$path}");
                }
                if ($path) {
                    $config['driverOptions'][$opt] = $path;
                }
            }
            if (getenv('DB_SSL_VERIFY') === 'false') {
                $config['driverOptions'][\PDO::MYSQL_ATTR_SSL_VERIFY_SERVER_CERT] = false;
            }
        }

        // Replicas
        if (getenv('DB_USE_REPLICAS') === 'true') {
            $primaryConfig = $config;
            $replicaHosts = explode(',', getenv('DB_REPLICA_HOSTS') ?: '');
            $replicas = [];

            foreach ($replicaHosts as $host) {
                $host = trim($host);
                if ($host) {
                    $replica = $primaryConfig;
                    $replica['host'] = $host;
                    $replicas[] = $replica;
                }
            }

            if (!empty($replicas)) {
                shuffle($replicas); // randomize replica choice for better load spreading
                $config['wrapperClass'] = PrimaryReadReplicaConnection::class;
                $config['primary'] = $primaryConfig;
                $config['replicas'] = $replicas;

                if (getenv('DB_KEEP_REPLICA') === 'true') {
                    $config['keepReplica'] = true;
                }
                unset($config['host'], $config['port'], $config['user'], $config['password'], $config['dbname']);
            } else {
                self::$logger->warning("DB_USE_REPLICAS enabled but no DB_REPLICA_HOSTS provided.");
            }
        }

        // Retry with backoff
        $maxAttempts = (int) (getenv('DB_RETRY_ATTEMPTS') ?: 5);
        $backoffBase = (int) (getenv('DB_RETRY_BACKOFF_MS') ?: 100);
        $attempts = 0;

        while ($attempts < $maxAttempts) {
            try {
                self::$conn = DriverManager::getConnection($config);
                self::$logger->info("Database connection established", [
                    'host' => $config['host'] ?? ($config['primary']['host'] ?? 'unknown'),
                    'dbname' => $config['dbname'] ?? ($config['primary']['dbname'] ?? 'unknown')
                ]);
                break;
            } catch (ConnectionException $e) {
                $attempts++;
                self::$logger->warning("DB connection attempt {$attempts} failed: {$e->getMessage()}");
                if ($attempts >= $maxAttempts) {
                    throw new RuntimeException("DB connection failed after {$attempts} attempts", 0, $e);
                }
                usleep($backoffBase * 1000 * (2 ** $attempts));
            }
        }
    }

    private static function isConnectionAlive(): bool
    {
        try {
            self::$conn->executeQuery('SELECT 1');
            return true;
        } catch (Exception $e) {
            self::$logger->warning("Connection health check failed: {$e->getMessage()}");
            return false;
        }
    }

    public static function getInstance(): DBALConnection
    {
        self::init();
        try {
            if (!self::$conn->isConnected() || !self::isConnectionAlive()) {
                self::$logger->warning("Connection lost, attempting to reconnect");
                self::$conn->close();
                self::$conn = null;
                self::init();
            }
        } catch (Exception $e) {
            self::$logger->error("Connection check failed: {$e->getMessage()}");
            self::$conn = null;
            self::init();
        }
        return self::$conn;
    }

    public static function getMysqlVersion(): string
    {
        if (self::$mysqlVersion === null) {
            try {
                $row = self::getInstance()->fetchAssociative("SELECT VERSION() AS version");
                self::$mysqlVersion = $row['version'] ?? 'unknown';
            } catch (Exception $e) {
                self::$logger->error("Failed to fetch MySQL version: {$e->getMessage()}");
                self::$mysqlVersion = 'unknown';
            }
        }
        return self::$mysqlVersion;
    }

    public static function createQueryBuilder(): QueryBuilder
    {
        return self::getInstance()->createQueryBuilder();
    }

    public static function getStats(): array
    {
        $conn = self::getInstance();
        $stats = [
            'is_connected'   => $conn->isConnected(),
            'mysql_version'  => self::getMysqlVersion(),
            'db_name'        => $conn->getDatabase(),
            'host'           => $conn->getParams()['host'] ?? 'multiple',
        ];
        if ($conn instanceof PrimaryReadReplicaConnection) {
            $stats['is_primary'] = $conn->isConnectedToPrimary();
        }
        return $stats;
    }

    public static function shutdown(): void
    {
        if (self::$conn !== null) {
            self::$conn->close();
            self::$conn = null;
            self::$mysqlVersion = null;
            self::$logger->info("Database connection closed");
        }
    }
}
