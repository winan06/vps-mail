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
 * users, so point them only at a throwaway server: setUp() refuses a server that has
 * the production database (see sharedServerRefusal()).
 */
abstract class DbTestCase extends TestCase
{
    protected const DATABASE = 'mailhost_test';

    /** The production database name. A server that has it is not disposable. */
    private const PRODUCTION_DATABASE = 'mailhost';

    /** Set to exactly "1" to run on a server that has the production database anyway. */
    private const ALLOW_SHARED_SERVER = 'MAILHOST_TEST_ALLOW_SHARED_SERVER';

    /** Connection variable to env-file key. */
    private const SERVER_VARIABLES = [
        'MAILHOST_TEST_DB_HOST' => 'DB_HOST',
        'MAILHOST_TEST_DB_PORT' => 'DB_PORT',
        'MAILHOST_TEST_DB_ROOT_PASSWORD' => 'DB_ROOT_PASSWORD',
    ];

    /**
     * Outcome of the shared-server check, made once per process: null before the first
     * test, '' when the server may be used, otherwise the refusal message.
     */
    private static ?string $sharedServerRefusal = null;

    /** The root connection pdo() hands out, released in tearDown(). */
    private ?PDO $rootConnection = null;

    protected function setUp(): void
    {
        parent::setUp();

        self::$sharedServerRefusal ??= $this->sharedServerRefusal(self::PRODUCTION_DATABASE) ?? '';
        if (self::$sharedServerRefusal !== '') {
            $this->fail(self::$sharedServerRefusal);
        }
    }

    protected function tearDown(): void
    {
        // PHPUnit keeps every test object until the run ends, so a connection held in a
        // property would stay open for the whole run and the suite would approach
        // max_connections. Release it as soon as the test is over.
        $this->rootConnection = null;

        parent::tearDown();
    }

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
     * A new root connection to the test server, on the test database unless $withDb is false.
     * Prefer pdo() for a connection the test keeps using.
     */
    protected function rootPdo(bool $withDb = true): PDO
    {
        return Connection::root($this->env(), $withDb);
    }

    /**
     * The root connection of the current test, on the test database: opened on first use and
     * closed in tearDown(). Call it after freshDatabase(), which drops the database it selects.
     */
    protected function pdo(): PDO
    {
        return $this->rootConnection ??= $this->rootPdo();
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

    /**
     * Why the integration tests must not run on this server, or null when they may.
     *
     * A server that has the database $production runs (or is being set up as) a real mail
     * system. The tests drop and re-create the server-wide accounts mail_ro, mail_policy,
     * mail_app, mail_portal and mailctl with random passwords, which would lock Postfix,
     * Dovecot, the portal and the job runner out of it.
     */
    protected function sharedServerRefusal(string $production): ?string
    {
        if (getenv(self::ALLOW_SHARED_SERVER) === '1') {
            return null;
        }

        $stmt = $this->rootPdo(false)->prepare('SELECT COUNT(*) FROM information_schema.schemata WHERE schema_name = ?');
        $stmt->execute([$production]);
        if ((int) $stmt->fetchColumn() === 0) {
            return null;
        }

        return "Refusing to run the integration tests: this server has a database named `$production`, so it "
            . 'looks like a real mail server. The tests drop and re-create the server-wide accounts mail_ro, '
            . 'mail_policy, mail_app, mail_portal and mailctl with random passwords, which would lock Postfix, '
            . 'Dovecot, the portal and the job runner out. Point MAILHOST_TEST_DB_HOST/PORT at a disposable '
            . 'MariaDB, or set ' . self::ALLOW_SHARED_SERVER . '=1 if losing those accounts is acceptable.';
    }
}
