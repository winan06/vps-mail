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

    public function test_tables_are_the_23_distinct_base_tables(): void
    {
        $this->assertCount(23, Grants::TABLES);
        $this->assertSame(Grants::TABLES, array_values(array_unique(Grants::TABLES)));
        $this->assertNotContains('schema_migrations', Grants::TABLES);
    }

    public function test_no_dangerous_grants(): void
    {
        $wildcards = [];
        foreach (Grants::USERS as $user) {
            foreach (Grants::forUser($user, 'mailhost') as $statement) {
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

        $this->assertSame(['mailctl: GRANT SELECT ON `mailhost`.*'], $wildcards);
    }

    public function test_mail_ro_reads_exactly_six_views(): void
    {
        $this->assertSame([
            'GRANT SELECT ON `mailhost`.`v_domains`',
            'GRANT SELECT ON `mailhost`.`v_mailboxes`',
            'GRANT SELECT ON `mailhost`.`v_auth`',
            'GRANT SELECT ON `mailhost`.`v_aliases`',
            'GRANT SELECT ON `mailhost`.`v_sender_login`',
            'GRANT SELECT ON `mailhost`.`v_rejected_recipients`',
        ], Grants::forUser('mail_ro', 'mailhost'));
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

    public function test_mail_app(): void
    {
        $expected = [];
        foreach (Grants::TABLES as $table) {
            if ($table !== 'audit_log') {
                $expected[] = "GRANT SELECT, INSERT, UPDATE, DELETE ON `mailhost`.`$table`";
            }
        }
        $expected[] = 'GRANT SELECT ON `mailhost`.`audit_log`';
        $expected[] = 'GRANT INSERT (' . self::AUDIT_COLUMNS . ') ON `mailhost`.`audit_log`';

        $statements = Grants::forUser('mail_app', 'mailhost');
        $this->assertSame($expected, $statements);
        $this->assertCount(24, $statements);
    }

    public function test_mail_portal(): void
    {
        $this->assertSame([
            'GRANT SELECT ON `mailhost`.`domains`',
            'GRANT SELECT ON `mailhost`.`mailboxes`',
            'GRANT SELECT ON `mailhost`.`lists`',
            'GRANT SELECT ON `mailhost`.`list_owners`',
            'GRANT SELECT ON `mailhost`.`settings`',
            'GRANT UPDATE (`password_hash`, `recovery_email`, `recovery_verified_at`, `password_changed_at`)'
                . ' ON `mailhost`.`mailboxes`',
            'GRANT SELECT, INSERT, UPDATE, DELETE ON `mailhost`.`forwarding_rules`',
            'GRANT SELECT, INSERT, UPDATE, DELETE ON `mailhost`.`list_members`',
            'GRANT SELECT, INSERT, UPDATE, DELETE ON `mailhost`.`otp_codes`',
            'GRANT SELECT, INSERT, UPDATE, DELETE ON `mailhost`.`sessions`',
            'GRANT INSERT (`job_type`, `payload`, `requested_by_type`, `requested_by_id`)'
                . ' ON `mailhost`.`v_portal_deployments`',
            'GRANT INSERT (' . self::AUDIT_COLUMNS . ') ON `mailhost`.`audit_log`',
        ], Grants::forUser('mail_portal', 'mailhost'));
    }

    public function test_mailctl(): void
    {
        $this->assertSame([
            'GRANT SELECT ON `mailhost`.*',
            'GRANT UPDATE ON `mailhost`.`deployments`',
            'GRANT SELECT, INSERT, UPDATE ON `mailhost`.`quarantine_items`',
            'GRANT UPDATE (`quota_used_bytes`, `usage_updated_at`) ON `mailhost`.`mailboxes`',
            'GRANT INSERT, UPDATE ON `mailhost`.`dkim_keys`',
            'GRANT DELETE ON `mailhost`.`mailboxes`',
            'GRANT DELETE ON `mailhost`.`domains`',
            'GRANT INSERT (' . self::AUDIT_COLUMNS . ') ON `mailhost`.`audit_log`',
        ], Grants::forUser('mailctl', 'mailhost'));
    }

    public function test_internal_helpers_and_migration_table_are_never_named(): void
    {
        foreach (Grants::USERS as $user) {
            foreach (Grants::forUser($user, 'mailhost') as $statement) {
                $this->assertStringNotContainsString('v_local_addresses', $statement, $user);
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
