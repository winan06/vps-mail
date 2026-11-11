<?php

declare(strict_types=1);

namespace Mailhost\Tests\Unit;

use InvalidArgumentException;
use Mailhost\Db\Grants;
use PHPUnit\Framework\TestCase;

/**
 * The privilege list of the five service accounts. These tests pin the statements
 * against the least-privilege table of the design, so a widened grant fails here
 * before any server is involved.
 */
final class GrantsTest extends TestCase
{
    private const AUDIT_COLUMNS = '`actor_type`, `actor_id`, `action`, `target_type`, `target_id`, `domain_id`, `ip`, `details`';

    public function test_users(): void
    {
        $this->assertSame(['mail_ro', 'mail_policy', 'mail_app', 'mail_portal', 'mailctl'], Grants::USERS);
    }

    public function test_tables_are_the_39_distinct_base_tables(): void
    {
        $this->assertCount(39, Grants::TABLES);
        $this->assertSame(Grants::TABLES, array_values(array_unique(Grants::TABLES)));
        $this->assertNotContains('schema_migrations', Grants::TABLES);
    }

    public function test_no_dangerous_grants(): void
    {
        $wildcards = [];
        foreach (['mailhost', 'mailhost_test'] as $db) {
            foreach (Grants::USERS as $user) {
                foreach (Grants::forUser($user, $db) as $statement) {
                    $this->assertStringStartsWith('GRANT ', $statement);
                    $this->assertStringNotContainsString('*.*', $statement, "$user: $statement");
                    $this->assertStringNotContainsString('ALL PRIVILEGES', $statement, "$user: $statement");
                    $this->assertStringNotContainsString('GRANT OPTION', $statement, "$user: $statement");
                    $this->assertStringNotContainsString(' TO ', $statement, "$user: the TO clause is added per host");

                    if (str_contains($statement, '`.*')) {
                        $wildcards[] = "$user: $statement";
                    }
                }
            }
        }

        // A name without "_" is used as is; "_" is escaped, see test_database_level_grant_escapes_underscores().
        $this->assertSame([
            'mailctl: GRANT SELECT ON `mailhost`.*',
            'mailctl: GRANT SELECT ON `mailhost\_test`.*',
        ], $wildcards);
    }

    public function test_database_level_grant_escapes_underscores(): void
    {
        // In a database-level grant "_" matches any single character, so an unescaped name would
        // also cover siblings such as mailhostXtest. Table-level grants take the name literally.
        $this->assertSame('GRANT SELECT ON `mailhost\_test`.*', Grants::forUser('mailctl', 'mailhost_test')[0]);
        $this->assertSame('GRANT SELECT ON `a\_b\_c`.*', Grants::forUser('mailctl', 'a_b_c')[0]);
        $this->assertSame('GRANT SELECT ON `mailhost`.*', Grants::forUser('mailctl', 'mailhost')[0]);

        $this->assertContains('GRANT UPDATE ON `mailhost_test`.`deployments`', Grants::forUser('mailctl', 'mailhost_test'));
        $this->assertSame(
            'GRANT SELECT ON `mailhost_test`.`v_auth`',
            Grants::forUser('mail_ro', 'mailhost_test')[2]
        );
    }

    /** Mail tables the admin application only reads (and, for login_events, appends to). */
    private const APP_READ_ONLY = ['login_events', 'delivery_events', 'dmarc_reports', 'dmarc_records', 'domain_checks'];

    /** New tables with an AUTO_INCREMENT id that mail_app writes through column-level grants. */
    private const APP_COLUMN_LEVEL = [
        'app_passwords', 'recovery_codes', 'sieve_rules', 'spam_sender_lists', 'release_requests', 'quota_requests', 'migration_jobs',
    ];

    private const LOGIN_EVENT_COLUMNS = '`at`, `subject_type`, `subject_id`, `login`, `service`, `result`, `ip`, `country`, '
        . '`client`, `app_password_id`';

    private const SIEVE_COLUMNS = '`mailbox_id`, `position`, `active`, `match_field`, `header_name`, `match_type`, '
        . '`match_value`, `action`, `folder`';

    private const SPAM_LIST_COLUMNS = '`mailbox_id`, `list_type`, `pattern`, `created_at`';

    public function test_app_tables_are_every_table_but_the_audit_log_and_the_history(): void
    {
        $this->assertSame(
            array_values(array_diff(Grants::TABLES, ['audit_log', 'log_cursors', ...self::APP_READ_ONLY])),
            Grants::APP_TABLES
        );
        $this->assertCount(32, Grants::APP_TABLES);
    }

    public function test_mail_ro_reads_exactly_eight_views(): void
    {
        $this->assertSame([
            'GRANT SELECT ON `mailhost`.`v_domains`',
            'GRANT SELECT ON `mailhost`.`v_mailboxes`',
            'GRANT SELECT ON `mailhost`.`v_auth`',
            'GRANT SELECT ON `mailhost`.`v_aliases`',
            'GRANT SELECT ON `mailhost`.`v_sender_login`',
            'GRANT SELECT ON `mailhost`.`v_rejected_recipients`',
            'GRANT SELECT ON `mailhost`.`v_app_auth`',
            'GRANT SELECT ON `mailhost`.`v_shared_acl`',
        ], Grants::forUser('mail_ro', 'mailhost'));
    }

    /**
     * No account may set an AUTO_INCREMENT id: a row inserted near the ceiling would wedge the
     * table for everyone. Column-level INSERT and UPDATE lists therefore never name `id`.
     */
    public function test_no_id_in_column_grants(): void
    {
        $lists = 0;
        foreach (Grants::USERS as $user) {
            foreach (Grants::forUser($user, 'mailhost') as $statement) {
                preg_match_all('/\\b(INSERT|UPDATE) \\(([^)]*)\\)/', $statement, $matches);
                foreach ($matches[2] as $columns) {
                    $lists++;
                    $this->assertNotContains('`id`', explode(', ', $columns), "$user: $statement");
                }
            }
        }
        $this->assertGreaterThan(20, $lists, 'the pattern should find the column lists');
    }

    public function test_id_table_columns_never_list_id(): void
    {
        foreach (Grants::ID_TABLE_COLUMNS as $table => $columns) {
            $this->assertContains($table, Grants::TABLES);
            $this->assertNotContains('id', $columns, $table);
            $this->assertSame($columns, array_values(array_unique($columns)), $table);
        }
    }

    public function test_mail_policy(): void
    {
        $this->assertSame([
            'GRANT SELECT ON `mailhost`.`v_domains`',
            'GRANT SELECT ON `mailhost`.`v_lists`',
            'GRANT SELECT ON `mailhost`.`v_list_sender_rules`',
            'GRANT SELECT ON `mailhost`.`v_login_roles`',
            'GRANT SELECT ON `mailhost`.`settings`',
            'GRANT INSERT (' . self::AUDIT_COLUMNS . ') ON `mailhost`.`audit_log`',
        ], Grants::forUser('mail_policy', 'mailhost'));
    }

    /**
     * Full row access to the APP_TABLES, except that the new tables with an id are written through
     * column-level grants without it; read access to the history tables, plus login_events inserts.
     * The column lists themselves are pinned against the schema by GrantsMatrixTest.
     */
    public function test_mail_app(): void
    {
        $expected = [];
        foreach (Grants::APP_TABLES as $table) {
            if (in_array($table, self::APP_COLUMN_LEVEL, true)) {
                $columns = '`' . implode('`, `', Grants::ID_TABLE_COLUMNS[$table]) . '`';
                $expected[] = "GRANT SELECT, DELETE ON `mailhost`.`$table`";
                $expected[] = "GRANT INSERT ($columns) ON `mailhost`.`$table`";
                $expected[] = "GRANT UPDATE ($columns) ON `mailhost`.`$table`";
            } else {
                $expected[] = "GRANT SELECT, INSERT, UPDATE, DELETE ON `mailhost`.`$table`";
            }
        }
        foreach (self::APP_READ_ONLY as $table) {
            $expected[] = "GRANT SELECT ON `mailhost`.`$table`";
        }
        $expected[] = 'GRANT INSERT (' . self::LOGIN_EVENT_COLUMNS . ') ON `mailhost`.`login_events`';
        $expected[] = 'GRANT SELECT ON `mailhost`.`audit_log`';
        $expected[] = 'GRANT INSERT (' . self::AUDIT_COLUMNS . ') ON `mailhost`.`audit_log`';

        $statements = Grants::forUser('mail_app', 'mailhost');
        $this->assertSame($expected, $statements);
        $this->assertCount(54, $statements);
        $this->assertNotContains('GRANT SELECT, INSERT, UPDATE, DELETE ON `mailhost`.`log_cursors`', $statements);
    }

    public function test_mail_portal(): void
    {
        $this->assertSame([
            'GRANT SELECT ON `mailhost`.`domains`',
            'GRANT SELECT ON `mailhost`.`mailboxes`',
            'GRANT SELECT ON `mailhost`.`lists`',
            'GRANT SELECT ON `mailhost`.`list_owners`',
            'GRANT SELECT ON `mailhost`.`settings`',
            'GRANT UPDATE (`password_hash`, `recovery_email`, `recovery_verified_at`, `password_changed_at`, `display_name`,'
                . ' `job_title`, `department`, `phone`, `directory_visible`, `require_app_passwords`, `must_change_password`)'
                . ' ON `mailhost`.`mailboxes`',
            'GRANT SELECT, INSERT, UPDATE, DELETE ON `mailhost`.`forwarding_rules`',
            'GRANT SELECT, INSERT, UPDATE, DELETE ON `mailhost`.`list_members`',
            'GRANT SELECT, INSERT, DELETE ON `mailhost`.`v_portal_sessions`',
            'GRANT UPDATE (`last_seen_at`, `expires_at`, `revoked_at`) ON `mailhost`.`v_portal_sessions`',
            'GRANT SELECT, DELETE ON `mailhost`.`v_portal_otp_codes`',
            'GRANT INSERT (`subject_type`, `subject_id`, `purpose`, `code_hmac`, `target`, `expires_at`, `attempts`,'
                . ' `used_at`, `request_ip`, `created_at`) ON `mailhost`.`v_portal_otp_codes`',
            'GRANT UPDATE (`attempts`, `used_at`) ON `mailhost`.`v_portal_otp_codes`',
            'GRANT INSERT (`job_type`, `payload`, `requested_by_type`, `requested_by_id`)'
                . ' ON `mailhost`.`v_portal_deployments`',
            'GRANT SELECT ON `mailhost`.`app_passwords`',
            'GRANT INSERT (`mailbox_id`, `name`, `password_hash`) ON `mailhost`.`app_passwords`',
            'GRANT UPDATE (`revoked_at`) ON `mailhost`.`app_passwords`',
            'GRANT SELECT, INSERT, DELETE ON `mailhost`.`v_portal_totp_secrets`',
            'GRANT UPDATE (`confirmed_at`, `last_used_step`) ON `mailhost`.`v_portal_totp_secrets`',
            'GRANT SELECT, DELETE ON `mailhost`.`v_portal_recovery_codes`',
            'GRANT INSERT (`subject_type`, `subject_id`, `code_hash`) ON `mailhost`.`v_portal_recovery_codes`',
            'GRANT UPDATE (`used_at`) ON `mailhost`.`v_portal_recovery_codes`',
            'GRANT SELECT ON `mailhost`.`v_portal_login_events`',
            'GRANT INSERT (' . self::LOGIN_EVENT_COLUMNS . ') ON `mailhost`.`v_portal_login_events`',
            'GRANT SELECT ON `mailhost`.`v_directory`',
            'GRANT SELECT ON `mailhost`.`shared_access`',
            'GRANT SELECT, DELETE ON `mailhost`.`sieve_rules`',
            'GRANT INSERT (' . self::SIEVE_COLUMNS . ') ON `mailhost`.`sieve_rules`',
            'GRANT UPDATE (' . self::SIEVE_COLUMNS . ') ON `mailhost`.`sieve_rules`',
            'GRANT SELECT, DELETE ON `mailhost`.`spam_sender_lists`',
            'GRANT INSERT (' . self::SPAM_LIST_COLUMNS . ') ON `mailhost`.`spam_sender_lists`',
            'GRANT UPDATE (' . self::SPAM_LIST_COLUMNS . ') ON `mailhost`.`spam_sender_lists`',
            'GRANT SELECT, INSERT, UPDATE, DELETE ON `mailhost`.`vacation_settings`',
            'GRANT SELECT ON `mailhost`.`release_requests`',
            'GRANT UPDATE (`status`, `requested_at`) ON `mailhost`.`release_requests`',
            'GRANT SELECT ON `mailhost`.`quota_requests`',
            'GRANT INSERT (`mailbox_id`, `requested_mb`, `note`) ON `mailhost`.`quota_requests`',
            'GRANT INSERT (' . self::AUDIT_COLUMNS . ') ON `mailhost`.`audit_log`',
        ], Grants::forUser('mail_portal', 'mailhost'));
    }

    /**
     * The portal reaches sessions, one-time codes, 2FA secrets, recovery codes and login events
     * only through its mailbox-only views, never through the tables that also hold admin rows.
     */
    public function test_portal_never_named_tables(): void
    {
        foreach (Grants::forUser('mail_portal', 'mailhost') as $statement) {
            foreach (['sessions', 'otp_codes', 'totp_secrets', 'recovery_codes', 'login_events'] as $table) {
                $this->assertStringNotContainsString("`$table`", $statement);
            }
        }
    }

    public function test_mailctl(): void
    {
        $this->assertSame([
            'GRANT SELECT ON `mailhost`.*',
            'GRANT UPDATE ON `mailhost`.`deployments`',
            'GRANT SELECT, INSERT, UPDATE ON `mailhost`.`quarantine_items`',
            'GRANT UPDATE (`quota_used_bytes`, `usage_updated_at`, `quota_warned_level`) ON `mailhost`.`mailboxes`',
            'GRANT INSERT, UPDATE ON `mailhost`.`dkim_keys`',
            'GRANT DELETE ON `mailhost`.`mailboxes`',
            'GRANT DELETE ON `mailhost`.`domains`',
            'GRANT INSERT (`job_type`, `payload`, `requested_by_type`, `requested_by_id`) ON `mailhost`.`deployments`',
            'GRANT INSERT (' . self::LOGIN_EVENT_COLUMNS . ') ON `mailhost`.`login_events`',
            'GRANT DELETE ON `mailhost`.`login_events`',
            'GRANT INSERT (`queue_id`, `at`, `sender`, `recipient`, `status`, `relay`, `dsn`, `reason`, `sender_domain_id`,'
                . ' `recipient_domain_id`) ON `mailhost`.`delivery_events`',
            'GRANT DELETE ON `mailhost`.`delivery_events`',
            'GRANT INSERT (`org_name`, `report_id`, `policy_domain`, `domain_id`, `date_begin`, `date_end`, `policy_p`,'
                . ' `received_at`) ON `mailhost`.`dmarc_reports`',
            'GRANT DELETE ON `mailhost`.`dmarc_reports`',
            'GRANT INSERT (`report_id`, `source_ip`, `count`, `disposition`, `dkim_result`, `spf_result`, `header_from`)'
                . ' ON `mailhost`.`dmarc_records`',
            'GRANT SELECT, INSERT, UPDATE, DELETE ON `mailhost`.`domain_checks`',
            'GRANT SELECT, INSERT, UPDATE, DELETE ON `mailhost`.`log_cursors`',
            'GRANT UPDATE (`last_used_at`) ON `mailhost`.`app_passwords`',
            'GRANT INSERT (`quarantine_item_id`, `mailbox_id`, `token_hash`, `status`, `expires_at`)'
                . ' ON `mailhost`.`release_requests`',
            'GRANT UPDATE (`status`) ON `mailhost`.`release_requests`',
            'GRANT UPDATE (`status`, `password_enc`, `messages_total`, `messages_copied`, `started_at`, `finished_at`, `error`)'
                . ' ON `mailhost`.`migration_jobs`',
            'GRANT INSERT (' . self::AUDIT_COLUMNS . ') ON `mailhost`.`audit_log`',
        ], Grants::forUser('mailctl', 'mailhost'));
    }

    public function test_internal_helpers_and_migration_table_are_never_named(): void
    {
        foreach (Grants::USERS as $user) {
            foreach (Grants::forUser($user, 'mailhost') as $statement) {
                $this->assertStringNotContainsString('v_local_addresses', $statement, $user);
                $this->assertStringNotContainsString('v_list_addresses', $statement, $user);
                $this->assertStringNotContainsString('v_rejected_local', $statement, $user);
                $this->assertStringNotContainsString('schema_migrations', $statement, $user);
            }
        }
    }

    public function test_database_name_is_used_as_given(): void
    {
        $this->assertSame(
            'GRANT SELECT ON `mailhost_test`.`v_auth`',
            Grants::forUser('mail_ro', 'mailhost_test')[2]
        );
    }

    public function test_rejects_unknown_user(): void
    {
        $this->expectException(InvalidArgumentException::class);
        Grants::forUser('root', 'mailhost');
    }

    /**
     * @dataProvider badDatabaseNames
     */
    public function test_rejects_bad_database_name(string $db): void
    {
        $this->expectException(InvalidArgumentException::class);
        Grants::forUser('mail_ro', $db);
    }

    /** @return array<string,array{string}> */
    public function badDatabaseNames(): array
    {
        return [
            'empty' => [''],
            'backtick' => ['mail`host'],
            'dash' => ['mail-host'],
            'uppercase' => ['MailHost'],
            'trailing newline' => ["mailhost\n"],
            'wildcard' => ['%'],
        ];
    }
}
