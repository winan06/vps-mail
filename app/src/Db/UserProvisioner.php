<?php

declare(strict_types=1);

namespace Mailhost\Db;

use InvalidArgumentException;
use PDO;
use RuntimeException;

/**
 * Creates the service accounts of Grants::USERS and sets their password and privileges.
 *
 * Provisioning is repeatable: for each host the account is created if missing, its password
 * is set (rotating it when the account exists), every privilege it holds is revoked and the
 * privileges of Grants::forUser are granted again. Stray grants therefore never survive.
 * Each host is a separate MariaDB account, for example 'mail_ro'@'localhost' for the unix
 * socket and 'mail_ro'@'127.0.0.1' for TCP.
 *
 * Passwords are limited to a conservative alphabet so they can be passed through env files
 * and shell commands untouched.
 */
final class UserProvisioner
{
    private const PASSWORD_PATTERN = '/^[A-Za-z0-9+\/=._~-]{24,128}\z/';

    /** Host part of an account name: a name, address or pattern such as 10.0.0.%, never a quote. */
    private const HOST_PATTERN = '/^[A-Za-z0-9._:%\/-]{1,60}\z/';

    /**
     * @param PDO          $root  root connection (exceptions on error)
     * @param list<string> $hosts host parts of the accounts, at least one
     *
     * @throws InvalidArgumentException when $db does not match /^[a-z0-9_]+$/ or a host is not valid
     */
    public function __construct(private readonly PDO $root, private readonly string $db, private readonly array $hosts)
    {
        // The same rule as Connection::ensureDatabase().
        if (preg_match('/^[a-z0-9_]+\z/', $db) !== 1) {
            throw new InvalidArgumentException("Invalid database name: $db");
        }
        if ($hosts === []) {
            throw new InvalidArgumentException('At least one host is required');
        }
        foreach ($hosts as $host) {
            if (!is_string($host) || preg_match(self::HOST_PATTERN, $host) !== 1) {
                throw new InvalidArgumentException('Invalid host for database users: ' . (is_string($host) ? $host : gettype($host)));
            }
        }
    }

    /**
     * Provisions one account on every host, in the order given to the constructor.
     *
     * @throws InvalidArgumentException when $user is not in Grants::USERS or the password is not
     *                                  24 to 128 characters of A-Z a-z 0-9 + / = . _ ~ -
     * @throws \PDOException            when the server refuses a statement
     */
    public function provision(string $user, string $password): void
    {
        self::assertValid($user, $password);
        $statements = Grants::forUser($user, $this->db);
        $quotedPassword = $this->quote($password);

        foreach ($this->hosts as $host) {
            $account = $this->quote($user) . '@' . $this->quote($host);

            $this->root->exec("CREATE USER IF NOT EXISTS $account");
            $this->root->exec("ALTER USER $account IDENTIFIED BY $quotedPassword");
            $this->root->exec("REVOKE ALL PRIVILEGES, GRANT OPTION FROM $account");
            foreach ($statements as $statement) {
                $this->root->exec("$statement TO $account");
            }
        }
    }

    /**
     * Provisions all of Grants::USERS, in that order. Every name and password is checked
     * before the server is touched, so a bad entry changes nothing.
     *
     * @param array<array-key,mixed> $passwordsByUser exactly one password per user in Grants::USERS
     *
     * @throws InvalidArgumentException when a user is unknown or missing, or a password is invalid
     * @throws \PDOException            when the server refuses a statement
     */
    public function provisionAll(array $passwordsByUser): void
    {
        foreach (array_keys($passwordsByUser) as $user) {
            if (!in_array($user, Grants::USERS, true)) {
                throw new InvalidArgumentException('Unknown database user: ' . $user);
            }
        }
        foreach (Grants::USERS as $user) {
            $password = $passwordsByUser[$user] ?? null;
            if (!is_string($password)) {
                throw new InvalidArgumentException("No password for database user $user");
            }
            self::assertValid($user, $password);
        }

        foreach (Grants::USERS as $user) {
            $this->provision($user, $passwordsByUser[$user]);
        }
    }

    private static function assertValid(string $user, string $password): void
    {
        if (!in_array($user, Grants::USERS, true)) {
            throw new InvalidArgumentException("Unknown database user: $user");
        }
        if (preg_match(self::PASSWORD_PATTERN, $password) !== 1) {
            // The password itself is never put in the message.
            throw new InvalidArgumentException(
                "Invalid password for $user: use 24 to 128 characters from A-Z a-z 0-9 + / = . _ ~ -"
            );
        }
    }

    private function quote(string $value): string
    {
        $quoted = $this->root->quote($value);
        if ($quoted === false) {
            throw new RuntimeException('The database driver cannot quote a value');
        }

        return $quoted;
    }
}
