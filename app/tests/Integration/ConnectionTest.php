<?php

declare(strict_types=1);

namespace Mailhost\Tests\Integration;

use InvalidArgumentException;
use Mailhost\Db\Connection;
use PDO;
use PDOException;

/**
 * The settings every connection from Connection must carry: a UTC session, native prepared
 * statements, one statement per call, and a validated database name.
 */
final class ConnectionTest extends DbTestCase
{
    private const PARSE_ERROR = 1064;

    protected function setUp(): void
    {
        parent::setUp();

        $this->freshDatabase();
    }

    public function test_session_time_zone_is_utc(): void
    {
        $this->assertSame('+00:00', $this->pdo()->query('SELECT @@session.time_zone')->fetchColumn());
    }

    public function test_prepares_are_native(): void
    {
        $this->assertFalse((bool) $this->pdo()->getAttribute(PDO::ATTR_EMULATE_PREPARES));
    }

    /**
     * Defence in depth: an injected "; DROP ..." must never run as a second statement, even
     * through exec(), which does not prepare. The Migrator already sends one statement at a time.
     */
    public function test_multi_statements_are_refused(): void
    {
        try {
            $this->pdo()->exec('SELECT 1; SELECT 2');
        } catch (PDOException $e) {
            $this->assertSame(self::PARSE_ERROR, $e->errorInfo[1] ?? null, $e->getMessage());

            return;
        }

        $this->fail('A multi-statement string was accepted');
    }

    /**
     * @dataProvider badDatabaseNames
     */
    public function test_ensure_database_rejects_bad_names(string $db): void
    {
        $this->expectException(InvalidArgumentException::class);

        Connection::ensureDatabase($this->rootPdo(false), $db);
    }

    /** @return array<string,array{string}> */
    public function badDatabaseNames(): array
    {
        return [
            'uppercase and hyphen' => ['Bad-Name'],
            'backtick' => ['mail`host'],
            'empty' => [''],
            'trailing newline' => ["mailhost_x\n"],
        ];
    }
}
