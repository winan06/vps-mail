<?php

declare(strict_types=1);

namespace Mailhost\Tests\Integration;

use PDO;

/**
 * Row builders for integration tests that need domains, mailboxes, aliases,
 * forwarding rules and lists.
 *
 * The using test class supplies the connection through pdo(). Every helper inserts
 * one logical record straight into the base tables and returns its id (or nothing),
 * so a test reads like the data it sets up.
 */
trait Fixtures
{
    /** Fake Argon2id hash: valid prefix, never verified. */
    private const ARGON = '$argon2id$v=19$m=65536,t=4,p=1$c29tZXNhbHQ$aGFzaGhhc2hoYXNoaGFzaA';

    /** Fake bcrypt hash: valid prefix, never verified. */
    private const BCRYPT = '$2y$10$abcdefghijklmnopqrstuuABCDEFGHIJKLMNOPQRSTUVWXYZ01234';

    /** Connection the fixtures write through. */
    abstract protected function pdo(): PDO;

    protected function domain(string $name, string $status = 'active'): int
    {
        return $this->insertRow('INSERT INTO domains (name, status) VALUES (?, ?)', [$name, $status]);
    }

    protected function aliasDomain(string $alias, int $targetId): void
    {
        $this->insertRow(
            'INSERT INTO domain_aliases (alias_domain, target_domain_id) VALUES (?, ?)',
            [$alias, $targetId]
        );
    }

    protected function mailbox(int $domainId, string $lp, string $status = 'active', string $hash = self::ARGON): int
    {
        return $this->insertRow(
            'INSERT INTO mailboxes (domain_id, local_part, password_hash, status) VALUES (?, ?, ?, ?)',
            [$domainId, $lp, $hash, $status]
        );
    }

    /**
     * An active alias with one target row per destination. $lp must not be empty.
     *
     * @param list<string> $destinations
     */
    protected function alias(int $domainId, string $lp, array $destinations): int
    {
        $aliasId = $this->insertRow('INSERT INTO aliases (domain_id, local_part) VALUES (?, ?)', [$domainId, $lp]);
        foreach ($destinations as $destination) {
            $this->insertRow('INSERT INTO alias_targets (alias_id, destination) VALUES (?, ?)', [$aliasId, $destination]);
        }

        return $aliasId;
    }

    /** An active forwarding rule created by an admin. */
    protected function forward(int $mailboxId, string $dest, bool $keepCopy): void
    {
        $this->insertRow(
            'INSERT INTO forwarding_rules (mailbox_id, destination, keep_copy, created_by_type, created_by_id) '
            . "VALUES (?, ?, ?, 'admin', 1)",
            [$mailboxId, $dest, (int) $keepCopy]
        );
    }

    protected function mailList(
        int $domainId,
        string $lp,
        string $scope = 'domain',
        string $status = 'active',
        ?int $maxKb = null
    ): int {
        return $this->insertRow(
            'INSERT INTO lists (domain_id, local_part, scope, status, max_message_kb) VALUES (?, ?, ?, ?, ?)',
            [$domainId, $lp, $scope, $status, $maxKb]
        );
    }

    protected function member(int $listId, int $mailboxId, string $status = 'active'): void
    {
        $this->insertRow(
            'INSERT INTO list_members (list_id, mailbox_id, status) VALUES (?, ?, ?)',
            [$listId, $mailboxId, $status]
        );
    }

    /**
     * First column of every result row, sorted as strings.
     *
     * @param list<mixed> $params
     *
     * @return list<string>
     */
    protected function col(string $sql, array $params = []): array
    {
        $stmt = $this->pdo()->prepare($sql);
        $stmt->execute($params);
        $values = $stmt->fetchAll(PDO::FETCH_COLUMN);
        sort($values, SORT_STRING);

        return $values;
    }

    /** @param list<mixed> $params */
    private function insertRow(string $sql, array $params): int
    {
        $this->pdo()->prepare($sql)->execute($params);

        return (int) $this->pdo()->lastInsertId();
    }
}
