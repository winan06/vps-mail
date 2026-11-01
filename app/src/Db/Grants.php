<?php

declare(strict_types=1);

namespace Mailhost\Db;

use InvalidArgumentException;

/**
 * The privileges of the five database accounts, one account per service.
 *
 * Each account sees only what its service needs:
 *
 *  - mail_ro: Postfix and Dovecot lookups, through six read-only views;
 *  - mail_policy: the list-sender policy service, through views, plus settings and audit_log inserts;
 *  - mail_app: the admin application, full access to the base tables except the audit log;
 *  - mail_portal: the public self-service portal, a few columns and tables, and nothing else;
 *  - mailctl: the root-run job runner, which reads everything and writes only what its jobs change.
 *
 * Nothing here grants a global privilege, GRANT OPTION or write access to audit_log rows
 * after insertion. The helper views v_local_addresses and v_rejected_local and the table
 * schema_migrations are never named; only mailctl, which reads the whole database, can see them.
 */
final class Grants
{
    public const USERS = ['mail_ro', 'mail_policy', 'mail_app', 'mail_portal', 'mailctl'];

    /** The base tables of the schema (everything except schema_migrations), in migration order. */
    public const TABLES = [
        'domains',
        'domain_aliases',
        'dkim_keys',
        'mailboxes',
        'aliases',
        'alias_targets',
        'forwarding_rules',
        'lists',
        'list_members',
        'list_owners',
        'list_sender_rules',
        'roles',
        'role_permissions',
        'admins',
        'admin_domains',
        'filter_global',
        'filter_policies',
        'quarantine_items',
        'otp_codes',
        'sessions',
        'audit_log',
        'deployments',
        'settings',
    ];

    /**
     * The audit_log columns a service may set. id and at are filled in by the server, so
     * no account can forge a row id or back-date an entry.
     */
    private const AUDIT_INSERT_COLUMNS = [
        'actor_type',
        'actor_id',
        'action',
        'target_type',
        'target_id',
        'domain_id',
        'ip',
        'details',
    ];

    private const ALL_ROW_PRIVILEGES = 'SELECT, INSERT, UPDATE, DELETE';

    /**
     * GRANT statements for one account on database $db, without the TO clause.
     *
     * @return list<string> for example "GRANT SELECT ON `mailhost`.`v_auth`"
     *
     * @throws InvalidArgumentException when $user is not one of USERS or $db does not match /^[a-z0-9_]+$/
     */
    public static function forUser(string $user, string $db): array
    {
        if (!in_array($user, self::USERS, true)) {
            throw new InvalidArgumentException("Unknown database user: $user");
        }
        if (preg_match('/^[a-z0-9_]+\z/', $db) !== 1) {
            throw new InvalidArgumentException("Invalid database name: $db");
        }

        return match ($user) {
            'mail_ro' => self::mailRo($db),
            'mail_policy' => self::mailPolicy($db),
            'mail_app' => self::mailApp($db),
            'mail_portal' => self::mailPortal($db),
            'mailctl' => self::mailctl($db),
        };
    }

    /** @return list<string> */
    private static function mailRo(string $db): array
    {
        return self::onEach('SELECT', $db, [
            'v_domains',
            'v_mailboxes',
            'v_auth',
            'v_aliases',
            'v_sender_login',
            'v_rejected_recipients',
        ]);
    }

    /** @return list<string> */
    private static function mailPolicy(string $db): array
    {
        return [
            ...self::onEach('SELECT', $db, ['v_domains', 'v_lists', 'v_list_sender_rules', 'v_login_roles', 'settings']),
            self::auditInsert($db),
        ];
    }

    /** @return list<string> */
    private static function mailApp(string $db): array
    {
        return [
            ...self::onEach(self::ALL_ROW_PRIVILEGES, $db, array_values(array_diff(self::TABLES, ['audit_log']))),
            self::grant('SELECT', $db, 'audit_log'),
            self::auditInsert($db),
        ];
    }

    /** @return list<string> */
    private static function mailPortal(string $db): array
    {
        return [
            ...self::onEach('SELECT', $db, ['domains', 'mailboxes', 'lists', 'list_owners', 'settings']),
            self::grant(
                self::columns('UPDATE', ['password_hash', 'recovery_email', 'recovery_verified_at', 'password_changed_at']),
                $db,
                'mailboxes'
            ),
            ...self::onEach(self::ALL_ROW_PRIVILEGES, $db, ['forwarding_rules', 'list_members', 'otp_codes', 'sessions']),
            // Queue-only: the portal can add a job but never read, change or delete one. The view's
            // CHECK OPTION limits the job to doveadm_kick requested by a mailbox.
            self::grant(
                self::columns('INSERT', ['job_type', 'payload', 'requested_by_type', 'requested_by_id']),
                $db,
                'v_portal_deployments'
            ),
            self::auditInsert($db),
        ];
    }

    /** @return list<string> */
    private static function mailctl(string $db): array
    {
        // In a database-level grant "_" is a wildcard for any one character, so the name must be
        // escaped or `mail_prod`.* would also cover a sibling database such as mailXprod.
        // Table-level grants take the name literally and need no escaping.
        $pattern = str_replace('_', '\\_', $db);

        return [
            "GRANT SELECT ON `$pattern`.*",
            self::grant('UPDATE', $db, 'deployments'),
            self::grant('SELECT, INSERT, UPDATE', $db, 'quarantine_items'),
            self::grant(self::columns('UPDATE', ['quota_used_bytes', 'usage_updated_at']), $db, 'mailboxes'),
            self::grant('INSERT, UPDATE', $db, 'dkim_keys'),
            self::grant('DELETE', $db, 'mailboxes'),
            self::grant('DELETE', $db, 'domains'),
            self::auditInsert($db),
        ];
    }

    private static function auditInsert(string $db): string
    {
        return self::grant(self::columns('INSERT', self::AUDIT_INSERT_COLUMNS), $db, 'audit_log');
    }

    /**
     * @param list<string> $objects
     *
     * @return list<string>
     */
    private static function onEach(string $privileges, string $db, array $objects): array
    {
        return array_map(static fn (string $object): string => self::grant($privileges, $db, $object), $objects);
    }

    private static function grant(string $privileges, string $db, string $object): string
    {
        return "GRANT $privileges ON `$db`.`$object`";
    }

    /**
     * A column-level privilege: "INSERT (`a`, `b`)".
     *
     * @param list<string> $columns
     */
    private static function columns(string $privilege, array $columns): string
    {
        return $privilege . ' (`' . implode('`, `', $columns) . '`)';
    }
}
