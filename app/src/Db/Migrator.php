<?php

declare(strict_types=1);

namespace Mailhost\Db;

use InvalidArgumentException;
use PDO;
use PDOException;

/**
 * Applies the numbered .sql files of a directory, once each, in version order.
 *
 * Files are named NNNN_name.sql (see FILE_PATTERN) and the version is the name
 * without ".sql". Applied versions are recorded in schema_migrations with the
 * sha256 of the file. Applied migrations are append-only: if one of their files
 * changed or disappeared, migrate() refuses to run anything. A migration is
 * recorded only after all its statements succeeded, and DDL is not transactional,
 * so a failed migration may leave earlier statements applied. Migration files
 * must therefore be safe to re-run.
 */
final class Migrator
{
    private const FILE_PATTERN = '/^(\d{4}_[a-z0-9_]+)\.sql$/';

    public function __construct(private readonly PDO $pdo, private readonly string $dir)
    {
    }

    /**
     * State of every known version, in version order. Applied versions whose file
     * is gone are still listed as applied; migrate() is what refuses them.
     *
     * @return array<string,'applied'|'pending'>
     */
    public function status(): array
    {
        $applied = $this->applied();
        $versions = array_unique([...array_keys($this->files()), ...array_keys($applied)]);
        sort($versions, SORT_STRING);

        $status = [];
        foreach ($versions as $version) {
            $status[$version] = isset($applied[$version]) ? 'applied' : 'pending';
        }

        return $status;
    }

    /**
     * Applies every pending migration.
     *
     * @return list<string> the versions applied, in order
     *
     * @throws MigrationException when an applied file changed or is missing, or a migration fails
     */
    public function migrate(): array
    {
        $files = $this->files();
        $this->ensureTable();
        $applied = $this->applied();

        // Verify the whole history before running anything new.
        foreach ($applied as $version => $recorded) {
            if (!isset($files[$version])) {
                throw new MigrationException(
                    "Migration $version is missing from {$this->dir}; applied migrations must not be removed"
                );
            }

            $actual = hash_file('sha256', $files[$version]);
            if ($actual === false) {
                throw new MigrationException("Cannot read migration $version: {$files[$version]}");
            }
            if (!hash_equals($recorded, $actual)) {
                throw new MigrationException(sprintf(
                    'Migration %s changed after it was applied (checksum %s, recorded %s); add a new migration instead of editing it',
                    $version,
                    $actual,
                    $recorded
                ));
            }
        }

        $done = [];
        foreach ($files as $version => $path) {
            if (isset($applied[$version])) {
                continue;
            }
            $this->apply($version, $path);
            $done[] = $version;
        }

        return $done;
    }

    /**
     * Migration files by version, in version order.
     *
     * @return array<string,string> version => path
     *
     * @throws MigrationException when the directory cannot be read
     */
    private function files(): array
    {
        $entries = is_dir($this->dir) ? scandir($this->dir) : false;
        if ($entries === false) {
            throw new MigrationException("Migrations directory not found or unreadable: {$this->dir}");
        }

        $files = [];
        foreach ($entries as $entry) {
            $path = $this->dir . '/' . $entry;
            if (preg_match(self::FILE_PATTERN, $entry, $match) === 1 && is_file($path)) {
                $files[$match[1]] = $path;
            }
        }
        ksort($files, SORT_STRING);

        return $files;
    }

    /**
     * Recorded versions and their checksums, in version order. Empty before the
     * first migrate(), so status() does not have to create the table.
     *
     * @return array<string,string>
     */
    private function applied(): array
    {
        $exists = $this->pdo->query(
            "SELECT 1 FROM information_schema.tables WHERE table_schema = DATABASE() AND table_name = 'schema_migrations'"
        )->fetchColumn();
        if ($exists === false) {
            return [];
        }

        return $this->pdo
            ->query('SELECT version, checksum FROM schema_migrations ORDER BY version')
            ->fetchAll(PDO::FETCH_KEY_PAIR);
    }

    private function ensureTable(): void
    {
        $this->pdo->exec(
            'CREATE TABLE IF NOT EXISTS schema_migrations ('
            . 'version VARCHAR(255) CHARACTER SET ascii COLLATE ascii_bin NOT NULL PRIMARY KEY, '
            . 'checksum CHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL, '
            . 'applied_at DATETIME NOT NULL'
            . ') ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci'
        );
    }

    private function apply(string $version, string $path): void
    {
        $sql = file_get_contents($path);
        if ($sql === false) {
            throw new MigrationException("Cannot read migration $version: $path");
        }

        try {
            $statements = SqlSplitter::split($sql);
        } catch (InvalidArgumentException $e) {
            throw new MigrationException("Migration $version is malformed: {$e->getMessage()}", 0, $e);
        }

        foreach ($statements as $index => $statement) {
            try {
                $this->pdo->exec($statement);
            } catch (PDOException $e) {
                throw new MigrationException(
                    sprintf('Migration %s failed at statement %d: %s', $version, $index + 1, $e->getMessage()),
                    0,
                    $e
                );
            }
        }

        // Hash the text that was just executed, which equals hash_file() of the file.
        $this->pdo
            ->prepare('INSERT INTO schema_migrations (version, checksum, applied_at) VALUES (?, ?, UTC_TIMESTAMP())')
            ->execute([$version, hash('sha256', $sql)]);
    }
}
