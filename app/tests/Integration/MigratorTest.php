<?php

declare(strict_types=1);

namespace Mailhost\Tests\Integration;

use Mailhost\Db\MigrationException;
use Mailhost\Db\Migrator;
use PDO;

final class MigratorTest extends DbTestCase
{
    private ?string $dir = null;

    protected function setUp(): void
    {
        parent::setUp();

        $dir = sys_get_temp_dir() . '/mailhost-migrations-' . bin2hex(random_bytes(6));
        $this->assertTrue(mkdir($dir, 0700));
        $this->dir = $dir;

        $this->freshDatabase();
    }

    protected function tearDown(): void
    {
        if ($this->dir !== null) {
            foreach (glob($this->dir . '/*') ?: [] as $file) {
                unlink($file);
            }
            rmdir($this->dir);
            $this->dir = null;
        }

        parent::tearDown();
    }

    private function write(string $name, string $sql): string
    {
        $path = $this->dir . '/' . $name;
        $this->assertNotFalse(file_put_contents($path, $sql));

        return $path;
    }

    private function migrator(): Migrator
    {
        return new Migrator($this->rootPdo(), (string) $this->dir);
    }

    /** @return array<string,string> version => checksum */
    private function recorded(): array
    {
        return $this->rootPdo()
            ->query('SELECT version, checksum FROM schema_migrations ORDER BY version')
            ->fetchAll(PDO::FETCH_KEY_PAIR);
    }

    private function tableExists(string $table): bool
    {
        $stmt = $this->rootPdo()->prepare(
            'SELECT COUNT(*) FROM information_schema.tables WHERE table_schema = DATABASE() AND table_name = ?'
        );
        $stmt->execute([$table]);

        return (int) $stmt->fetchColumn() === 1;
    }

    private function assertRefused(string $pattern): void
    {
        try {
            $this->migrator()->migrate();
        } catch (MigrationException $e) {
            $this->assertMatchesRegularExpression($pattern, $e->getMessage());

            return;
        }

        $this->fail('Expected MigrationException matching ' . $pattern);
    }

    public function test_applies_pending_in_order_and_records(): void
    {
        // 0002 needs the table that 0001 creates, so the order matters.
        $second = $this->write('0002_b.sql', "INSERT IGNORE INTO a (x) VALUES (1);\n");
        $first = $this->write('0001_a.sql', "CREATE TABLE IF NOT EXISTS a (x INT PRIMARY KEY);\n");

        $this->assertSame(['0001_a', '0002_b'], $this->migrator()->migrate());

        $this->assertSame(
            [
                '0001_a' => hash_file('sha256', $first),
                '0002_b' => hash_file('sha256', $second),
            ],
            $this->recorded()
        );
        $this->assertSame(
            '1',
            (string) $this->rootPdo()->query('SELECT COUNT(*) FROM a')->fetchColumn()
        );
    }

    public function test_second_run_applies_nothing(): void
    {
        $this->write('0001_a.sql', "CREATE TABLE IF NOT EXISTS a (x INT);\n");

        $migrator = $this->migrator();
        $this->assertSame(['0001_a'], $migrator->migrate());
        $this->assertSame([], $migrator->migrate());
    }

    public function test_changed_applied_file_is_refused(): void
    {
        $this->write('0001_a.sql', "CREATE TABLE IF NOT EXISTS a (x INT);\n");
        $this->migrator()->migrate();

        $this->write('0003_c.sql', "CREATE TABLE IF NOT EXISTS c (x INT);\n");
        $this->write('0001_a.sql', "CREATE TABLE IF NOT EXISTS a (x INT, y INT);\n");

        $this->assertRefused('/0001_a.*checksum/');

        $this->assertSame(['0001_a'], array_keys($this->recorded()));
        $this->assertFalse($this->tableExists('c'), '0003_c must not run when an applied file changed');
    }

    public function test_missing_applied_file_is_refused(): void
    {
        $path = $this->write('0001_a.sql', "CREATE TABLE IF NOT EXISTS a (x INT);\n");
        $this->migrator()->migrate();

        $this->write('0002_b.sql', "CREATE TABLE IF NOT EXISTS b (x INT);\n");
        unlink($path);

        $this->assertRefused('/0001_a.*missing/');

        $this->assertSame(['0001_a'], array_keys($this->recorded()));
        $this->assertFalse($this->tableExists('b'), '0002_b must not run when an applied file is missing');
    }

    public function test_failed_statement_is_not_recorded(): void
    {
        $this->write('0001_a.sql', "CREATE TABLE ok (x INT);\nNOT SQL;\n");

        $this->assertRefused('/0001_a.*statement 2/');
        $this->assertSame(['0001_a' => 'pending'], $this->migrator()->status());
        $this->assertSame([], $this->recorded());

        // The first statement did run, so the corrected file must be re-runnable.
        $this->write('0001_a.sql', "CREATE TABLE IF NOT EXISTS ok (x INT);\n");
        $this->assertSame(['0001_a'], $this->migrator()->migrate());
    }

    public function test_ignores_non_migration_files(): void
    {
        $this->write('README.md', "notes\n");
        $this->write('1_bad.sql', "SELECT 1;\n");
        $this->write('0003_UPPER.sql', "SELECT 1;\n");
        $this->write('0001_a.sql', "CREATE TABLE IF NOT EXISTS a (x INT);\n");
        $this->write('0002_b.sql', "CREATE TABLE IF NOT EXISTS b (x INT);\n");

        // status() must work before the bookkeeping table exists.
        $this->assertSame(['0001_a' => 'pending', '0002_b' => 'pending'], $this->migrator()->status());

        $this->assertSame(['0001_a', '0002_b'], $this->migrator()->migrate());
        $this->assertSame(['0001_a' => 'applied', '0002_b' => 'applied'], $this->migrator()->status());
    }
}
