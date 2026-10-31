<?php

declare(strict_types=1);

namespace Mailhost\Tests\Integration;

use Mailhost\Db\Connection;
use Mailhost\Db\Migrator;
use PDO;
use PHPUnit\Framework\TestCase;

/**
 * Base class for tests that need a disposable MariaDB server.
 *
 * Connection details come from MAILHOST_TEST_DB_HOST, MAILHOST_TEST_DB_PORT and
 * MAILHOST_TEST_DB_ROOT_PASSWORD. The tests run as root and create server-wide
 * users, so point them only at a throwaway server.
 */
abstract class DbTestCase extends TestCase
{
    protected const DATABASE = 'mailhost_test';

    /** Connection variable to env-file key. */
    private const SERVER_VARIABLES = [
        'MAILHOST_TEST_DB_HOST' => 'DB_HOST',
        'MAILHOST_TEST_DB_PORT' => 'DB_PORT',
        'MAILHOST_TEST_DB_ROOT_PASSWORD' => 'DB_ROOT_PASSWORD',
    ];

    /**
     * Env array for Connection, with DB_NAME set to the test database.
     *
     * @return array<string,string>
     */
    protected function env(): array
    {
        $env = [];
        $missing = [];
        foreach (self::SERVER_VARIABLES as $variable => $key) {
            $value = getenv($variable);
            if ($value === false || $value === '') {
                $missing[] = $variable;
                continue;
            }
            $env[$key] = $value;
        }

        if ($missing !== []) {
            $this->fail(
                'Missing ' . implode(', ', $missing) . '. Integration tests need a disposable MariaDB: export '
                . implode(', ', array_keys(self::SERVER_VARIABLES)) . ' before running them.'
            );
        }

        $env['DB_NAME'] = self::DATABASE;

        return $env;
    }

    /**
     * Root connection to the test server, on the test database unless $withDb is false.
     */
    protected function rootPdo(bool $withDb = true): PDO
    {
        return Connection::root($this->env(), $withDb);
    }

    /** Drops and recreates the test database. */
    protected function freshDatabase(): void
    {
        $pdo = $this->rootPdo(false);
        $pdo->exec('DROP DATABASE IF EXISTS `' . self::DATABASE . '`');
        Connection::ensureDatabase($pdo, self::DATABASE);
    }

    /** Applies every migration in app/migrations to the test database. */
    protected function migrateAll(): void
    {
        (new Migrator($this->rootPdo(), dirname(__DIR__, 2) . '/migrations'))->migrate();
    }
}
