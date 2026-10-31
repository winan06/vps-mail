<?php

declare(strict_types=1);

namespace Mailhost\Db;

use InvalidArgumentException;
use PDO;

/**
 * Opens PDO connections with the settings every mailhost connection needs:
 * exception errors, native prepared statements, utf8mb4 and a UTC session.
 */
final class Connection
{
    private const DEFAULT_DATABASE = 'mailhost';
    private const DEFAULT_SOCKET = '/run/mysqld/mysqld.sock';
    private const DEFAULT_PORT = '3306';

    /**
     * Connects as the database root user.
     *
     * Uses TCP (DB_HOST, DB_PORT, DB_ROOT_PASSWORD) when DB_HOST is set, otherwise
     * the unix socket DB_SOCKET without a password. The user is DB_ROOT_USER
     * (default "root"). With $withDb the connection selects DB_NAME (default "mailhost").
     *
     * @param array<string,string> $env
     *
     * @throws InvalidArgumentException when DB_NAME is not a safe database name
     * @throws \PDOException when the server cannot be reached
     */
    public static function root(array $env, bool $withDb = true): PDO
    {
        $user = self::value($env, 'DB_ROOT_USER') ?? 'root';
        $host = self::value($env, 'DB_HOST');

        if ($host !== null) {
            $dsn = 'mysql:host=' . $host . ';port=' . (self::value($env, 'DB_PORT') ?? self::DEFAULT_PORT);
            $password = $env['DB_ROOT_PASSWORD'] ?? '';
        } else {
            $dsn = 'mysql:unix_socket=' . (self::value($env, 'DB_SOCKET') ?? self::DEFAULT_SOCKET);
            $password = '';
        }

        if ($withDb) {
            $dsn .= ';dbname=' . self::databaseName($env);
        }

        return self::open($dsn, $user, $password);
    }

    /**
     * Connects over TCP as an application user, on the DB_NAME database.
     *
     * @param array<string,string> $env DB_HOST (default 127.0.0.1), DB_PORT (default 3306), DB_NAME
     *
     * @throws InvalidArgumentException when DB_NAME is not a safe database name
     * @throws \PDOException when the connection or login fails
     */
    public static function asUser(array $env, string $user, string $password): PDO
    {
        $dsn = sprintf(
            'mysql:host=%s;port=%s;dbname=%s',
            self::value($env, 'DB_HOST') ?? '127.0.0.1',
            self::value($env, 'DB_PORT') ?? self::DEFAULT_PORT,
            self::databaseName($env)
        );

        return self::open($dsn, $user, $password);
    }

    /**
     * Creates the database if it does not exist yet.
     *
     * @throws InvalidArgumentException when $db does not match /^[a-z0-9_]+$/
     */
    public static function ensureDatabase(PDO $rootNoDb, string $db): void
    {
        self::assertDatabaseName($db);

        $rootNoDb->exec(
            'CREATE DATABASE IF NOT EXISTS `' . $db . '` CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci'
        );
    }

    private static function open(string $dsn, string $user, string $password): PDO
    {
        return new PDO($dsn . ';charset=utf8mb4', $user, $password, [
            PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
            PDO::ATTR_EMULATE_PREPARES => false,
            PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
            PDO::MYSQL_ATTR_INIT_COMMAND => "SET time_zone = '+00:00'",
        ]);
    }

    /** @param array<string,string> $env */
    private static function databaseName(array $env): string
    {
        $db = self::value($env, 'DB_NAME') ?? self::DEFAULT_DATABASE;
        self::assertDatabaseName($db);

        return $db;
    }

    private static function assertDatabaseName(string $db): void
    {
        if (preg_match('/^[a-z0-9_]+$/', $db) !== 1) {
            throw new InvalidArgumentException("Invalid database name: $db");
        }
    }

    /**
     * An env value, or null when the key is absent or empty.
     *
     * @param array<string,string> $env
     */
    private static function value(array $env, string $key): ?string
    {
        $value = $env[$key] ?? '';

        return $value === '' ? null : $value;
    }
}
