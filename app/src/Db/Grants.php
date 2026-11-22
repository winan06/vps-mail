<?php

declare(strict_types=1);

namespace Mailhost\Db;

use InvalidArgumentException;

/**
 * The privileges of the five database accounts, one account per service.
 *
 * Each account sees only what its service needs:
 *
 *  - mail_ro: Postfix and Dovecot lookups, through eight read-only views;
 *  - mail_policy: the list-sender policy service, through views, plus settings and audit_log inserts;
 *  - mail_app: the admin application, row access to APP_TABLES, read access to the history
 *    tables (audit log, login and delivery events, DMARC reports, domain checks);
 *  - mail_portal: the public self-service portal, a few columns and tables, and its sessions,
 *    one-time codes, 2FA secrets, recovery codes, login events and job requests only through
 *    the mailbox-only portal views of 0006 and 0014;
 *  - mailctl: the root-run job runner, which reads everything and writes only what its jobs change.
 *
 * Nothing here grants a global privilege, GRANT OPTION or write access to audit_log rows
 * after insertion. No account may set the AUTO_INCREMENT id of a table added in 0008 to 0011:
 * those tables are written through column-level grants (ID_TABLE_COLUMNS), because a row
 * inserted near the id ceiling would wedge the table. The helper views v_local_addresses,
 * v_list_addresses and v_rejected_local and the table schema_migrations are never named; only
 * mailctl, which reads the whole database, can see them.
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
        'app_passwords',
        'totp_secrets',
        'recovery_codes',
        'login_events',
        'delivery_events',
        'log_cursors',
        'sieve_rules',
        'vacation_settings',
        'spam_sender_lists',
        'shared_access',
        'release_requests',
        'quota_requests',
        'domain_checks',
        'dmarc_reports',
        'dmarc_records',
        'migration_jobs',
    ];

    /**
     * The tables the admin application reads and writes rows of: every base table except the
     * audit log and the history that only mailctl writes (login and delivery events, DMARC
     * reports, domain checks, log cursors). The tables of 0008 to 0011 with an id are written
     * through column-level grants without it.
     */
    public const APP_TABLES = [
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
        'deployments',
        'settings',
        'app_passwords',
        'totp_secrets',
        'recovery_codes',
        'sieve_rules',
        'vacation_settings',
        'spam_sender_lists',
        'shared_access',
        'release_requests',
        'quota_requests',
        'migration_jobs',
    ];

    /**
     * Every column except id, in table order, of each table added in 0008 to 0011 that has an
     * AUTO_INCREMENT id and is written by a service. GrantsMatrixTest pins these lists against
     * the schema.
     */
    public const ID_TABLE_COLUMNS = [
        'app_passwords' => ['mailbox_id', 'name', 'password_hash', 'created_at', 'last_used_at', 'revoked_at'],
        'recovery_codes' => ['subject_type', 'subject_id', 'code_hash', 'used_at', 'created_at'],
        'login_events' => [
            'at', 'subject_type', 'subject_id', 'login', 'service', 'result', 'ip', 'country', 'client', 'app_password_id',
        ],
        'delivery_events' => [
            'queue_id', 'at', 'sender', 'recipient', 'status', 'relay', 'dsn', 'reason', 'sender_domain_id', 'recipient_domain_id',
        ],
        'sieve_rules' => [
            'mailbox_id', 'position', 'active', 'match_field', 'header_name', 'match_type', 'match_value', 'action', 'folder',
        ],
        'spam_sender_lists' => ['mailbox_id', 'list_type', 'pattern', 'created_at'],
        'release_requests' => [
            'quarantine_item_id', 'mailbox_id', 'token_hash', 'status', 'requested_at', 'decided_at', 'decided_by', 'expires_at',
        ],
        'quota_requests' => ['mailbox_id', 'requested_mb', 'note', 'status', 'created_at', 'decided_at', 'decided_by'],
        'dmarc_reports' => [
            'org_name', 'report_id', 'policy_domain', 'domain_id', 'date_begin', 'date_end', 'policy_p', 'received_at',
        ],
        'dmarc_records' => ['report_id', 'source_ip', 'count', 'disposition', 'dkim_result', 'spf_result', 'header_from'],
        'migration_jobs' => [
            'mailbox_id', 'host', 'port', 'tls', 'username', 'password_enc', 'status', 'messages_total', 'messages_copied',
            'error', 'created_by', 'created_at', 'started_at', 'finished_at', 'expires_at',
        ],
    ];

    /**
     * The login_events columns the portal and the admin application may set: every column but
     * id and `at`, so neither can back-date a login. Only mailctl's log ingest sets `at`.
     */
    private const LOGIN_EVENT_COLUMNS_NO_AT = [
        'subject_type', 'subject_id', 'login', 'service', 'result', 'ip', 'country', 'client', 'app_password_id',
    ];

    /** History tables the admin application may read but not change. */
    private const APP_READ_ONLY = ['login_events', 'delivery_events', 'dmarc_reports', 'dmarc_records', 'domain_checks'];

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
            'v_app_auth',
            'v_shared_acl',
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
        $statements = [];
        foreach (self::APP_TABLES as $table) {
            if (isset(self::ID_TABLE_COLUMNS[$table])) {
                $statements[] = self::grant('SELECT, DELETE', $db, $table);
                $statements[] = self::withoutId('INSERT', $db, $table);
                $statements[] = self::withoutId('UPDATE', $db, $table);
            } else {
                $statements[] = self::grant(self::ALL_ROW_PRIVILEGES, $db, $table);
            }
        }

        return [
            ...$statements,
            ...self::onEach('SELECT', $db, self::APP_READ_ONLY),
            self::grant(self::columns('INSERT', self::LOGIN_EVENT_COLUMNS_NO_AT), $db, 'login_events'),
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
                self::columns('UPDATE', [
                    'password_hash',
                    'recovery_email',
                    'recovery_verified_at',
                    'password_changed_at',
                    'display_name',
                    'job_title',
                    'department',
                    'phone',
                    'directory_visible',
                    'require_app_passwords',
                    'must_change_password',
                ]),
                $db,
                'mailboxes'
            ),
            ...self::onEach(self::ALL_ROW_PRIVILEGES, $db, ['forwarding_rules', 'list_members']),
            // Sessions and one-time codes only through views that hold mailbox rows: the portal can
            // never read, create or redeem an admin session or code. Who a row belongs to and its
            // secret are fixed once written; only the columns a login or code check updates change.
            self::grant('SELECT, INSERT, DELETE', $db, 'v_portal_sessions'),
            self::grant(self::columns('UPDATE', ['last_seen_at', 'expires_at', 'revoked_at']), $db, 'v_portal_sessions'),
            self::grant('SELECT, DELETE', $db, 'v_portal_otp_codes'),
            // Every column but id: an id near the AUTO_INCREMENT ceiling would wedge the table.
            self::grant(
                self::columns('INSERT', [
                    'subject_type',
                    'subject_id',
                    'purpose',
                    'code_hmac',
                    'target',
                    'expires_at',
                    'attempts',
                    'used_at',
                    'request_ip',
                    'created_at',
                ]),
                $db,
                'v_portal_otp_codes'
            ),
            self::grant(self::columns('UPDATE', ['attempts', 'used_at']), $db, 'v_portal_otp_codes'),
            // Queue-only: the portal can add a job but never read, change or delete one. The view's
            // CHECK OPTION (0014) limits it to doveadm_kick, sieve_compile or spam_lists, requested by
            // a named mailbox, with a payload of exactly {"mailbox_id": <that mailbox>}.
            self::grant(
                self::columns('INSERT', ['job_type', 'payload', 'requested_by_type', 'requested_by_id']),
                $db,
                'v_portal_deployments'
            ),
            // App passwords: created with a fresh hash, then only ever revoked.
            self::grant('SELECT', $db, 'app_passwords'),
            self::grant(self::columns('INSERT', ['mailbox_id', 'name', 'password_hash']), $db, 'app_passwords'),
            self::grant(self::columns('UPDATE', ['revoked_at']), $db, 'app_passwords'),
            // 2FA secrets, recovery codes and the portal's own login events only through the
            // mailbox-only views of 0014.
            self::grant('SELECT, INSERT, DELETE', $db, 'v_portal_totp_secrets'),
            self::grant(self::columns('UPDATE', ['confirmed_at', 'last_used_step']), $db, 'v_portal_totp_secrets'),
            self::grant('SELECT, DELETE', $db, 'v_portal_recovery_codes'),
            self::grant(self::columns('INSERT', ['subject_type', 'subject_id', 'code_hash']), $db, 'v_portal_recovery_codes'),
            self::grant(self::columns('UPDATE', ['used_at']), $db, 'v_portal_recovery_codes'),
            self::grant('SELECT', $db, 'v_portal_login_events'),
            self::grant(self::columns('INSERT', self::LOGIN_EVENT_COLUMNS_NO_AT), $db, 'v_portal_login_events'),
            // "Recent activity": every login event of a mailbox, read-only.
            self::grant('SELECT', $db, 'v_portal_activity'),
            // The address book, and the shared mailboxes a user belongs to.
            ...self::onEach('SELECT', $db, ['v_directory', 'shared_access']),
            // Mail rules and spam lists: the user's own rows, every column but id.
            ...self::ownRows($db, 'sieve_rules'),
            ...self::ownRows($db, 'spam_sender_lists'),
            self::grant(self::ALL_ROW_PRIVILEGES, $db, 'vacation_settings'),
            // A release request is turned from 'offered' into 'requested' only through the view of
            // 0014, whose CHECK OPTION refuses any other status: an admin decides it.
            self::grant('SELECT', $db, 'release_requests'),
            self::grant('SELECT', $db, 'v_portal_release_requests'),
            self::grant(self::columns('UPDATE', ['status', 'requested_at']), $db, 'v_portal_release_requests'),
            // A quota request is created pending; an admin decides it.
            self::grant('SELECT', $db, 'quota_requests'),
            self::grant(self::columns('INSERT', ['mailbox_id', 'requested_mb', 'note']), $db, 'quota_requests'),
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
            self::grant(self::columns('UPDATE', ['quota_used_bytes', 'usage_updated_at', 'quota_warned_level']), $db, 'mailboxes'),
            self::grant('INSERT, UPDATE', $db, 'dkim_keys'),
            self::grant('DELETE', $db, 'mailboxes'),
            self::grant('DELETE', $db, 'domains'),
            // mailbox_archive also removes the mailbox's 2FA secret and recovery codes, which
            // have no foreign key to cascade from.
            self::grant('DELETE', $db, 'totp_secrets'),
            self::grant('DELETE', $db, 'recovery_codes'),
            // Follow-up jobs, such as domain_check after a DNS change.
            self::grant(self::columns('INSERT', ['job_type', 'payload', 'requested_by_type', 'requested_by_id']), $db, 'deployments'),
            // Log ingest and retention.
            self::withoutId('INSERT', $db, 'login_events'),
            self::grant('DELETE', $db, 'login_events'),
            self::withoutId('INSERT', $db, 'delivery_events'),
            self::grant('DELETE', $db, 'delivery_events'),
            self::withoutId('INSERT', $db, 'dmarc_reports'),
            self::grant('DELETE', $db, 'dmarc_reports'),
            self::withoutId('INSERT', $db, 'dmarc_records'),
            ...self::onEach(self::ALL_ROW_PRIVILEGES, $db, ['domain_checks', 'log_cursors']),
            self::grant(self::columns('UPDATE', ['last_used_at']), $db, 'app_passwords'),
            // The quarantine digest offers release links; expiry marks them.
            self::grant(
                self::columns('INSERT', ['quarantine_item_id', 'mailbox_id', 'token_hash', 'status', 'expires_at']),
                $db,
                'release_requests'
            ),
            self::grant(self::columns('UPDATE', ['status']), $db, 'release_requests'),
            // imap_migrate reports progress and must clear the old password when the job ends.
            self::grant(
                self::columns('UPDATE', [
                    'status',
                    'password_enc',
                    'messages_total',
                    'messages_copied',
                    'started_at',
                    'finished_at',
                    'error',
                ]),
                $db,
                'migration_jobs'
            ),
            self::auditInsert($db),
        ];
    }

    /** A column-level INSERT or UPDATE on every column of $table except id. */
    private static function withoutId(string $privilege, string $db, string $table): string
    {
        return self::grant(self::columns($privilege, self::ID_TABLE_COLUMNS[$table]), $db, $table);
    }

    /**
     * Read, delete, and insert or update every column but id: for portal tables of the user's
     * own rows. Which rows are the user's is the portal's check.
     *
     * @return list<string>
     */
    private static function ownRows(string $db, string $table): array
    {
        return [
            self::grant('SELECT, DELETE', $db, $table),
            self::withoutId('INSERT', $db, $table),
            self::withoutId('UPDATE', $db, $table),
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
