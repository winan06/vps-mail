<?php

declare(strict_types=1);

namespace Mailhost\Tests\Integration;

use Mailhost\Db\SqlSplitter;
use PDO;
use PDOException;

/**
 * The views behind the list-sender policy service and the portal job queue (migration 0006).
 *
 * v_lists, v_list_sender_rules and v_login_roles are read by mail_policy; v_portal_deployments
 * is the only way mail_portal may queue a job, so its WITH CASCADED CHECK OPTION must refuse
 * every job that is not a doveadm_kick requested by a mailbox. A refused row fails with
 * MariaDB error 1369 (CHECK OPTION failed), asserted on errorInfo[1], never on the message.
 */
final class PolicyViewsTest extends DbTestCase
{
    use Fixtures;

    private const CHECK_OPTION_FAILED = 1369;
    private const UNKNOWN_COLUMN = 1054;

    private const KICK = 'INSERT INTO v_portal_deployments (job_type, payload, requested_by_type, requested_by_id) '
        . 'VALUES (?, ?, ?, ?)';

    private PDO $pdo;

    private int $example;
    private int $other;
    private int $alice;
    private int $bob;
    private int $carol;
    private int $erin;
    private int $team;
    private int $big;
    private int $old;
    private int $gone;

    protected function setUp(): void
    {
        parent::setUp();

        $this->freshDatabase();
        $this->migrateAll();
        $this->pdo = $this->rootPdo();
        $this->buildFixture();
    }

    protected function pdo(): PDO
    {
        return $this->pdo;
    }

    /**
     * example.com is active and other.org is suspended.
     *
     * - alice and carol: active mailboxes. bob: suspended. erin: active, but on other.org.
     * - team@: active universal list, no size limit of its own.
     * - big@: active domain list, 512 KB limit.
     * - old@: suspended list. gone@other.org: active list on the suspended domain.
     * - Sender rules: team has (any_authenticated, '') and (domain, example.com); big has
     *   (address, bob@example.com); old and gone have one rule each.
     * - Admins: root (super_admin, alice) is the only one that counts. The others are
     *   suspended (carol), on a suspended mailbox (bob), on a mailbox of a suspended
     *   domain (erin), or have no mailbox.
     */
    private function buildFixture(): void
    {
        $this->example = $this->domain('example.com');
        $this->other = $this->domain('other.org', 'suspended');

        $this->alice = $this->mailbox($this->example, 'alice');
        $this->bob = $this->mailbox($this->example, 'bob', 'suspended');
        $this->carol = $this->mailbox($this->example, 'carol');
        $this->erin = $this->mailbox($this->other, 'erin');

        $this->team = $this->mailList($this->example, 'team', 'universal');
        $this->big = $this->mailList($this->example, 'big', 'domain', 'active', 512);
        $this->old = $this->mailList($this->example, 'old', 'domain', 'suspended');
        $this->gone = $this->mailList($this->other, 'gone');

        $this->rule($this->team, 'any_authenticated', '');
        $this->rule($this->team, 'domain', 'example.com');
        $this->rule($this->big, 'address', 'bob@example.com');
        $this->rule($this->old, 'address', 'alice@example.com');
        $this->rule($this->gone, 'role', 'super_admin');

        $this->admin('root', 'super_admin', $this->alice);
        $this->admin('sleepy', 'domain_admin', $this->carol, 'suspended');
        $this->admin('onbob', 'domain_admin', $this->bob);
        $this->admin('onerin', 'domain_admin', $this->erin);
        $this->admin('nobox', 'super_admin', null);
    }

    // ---- helpers -----------------------------------------------------------------

    private function rule(int $listId, string $type, string $value): void
    {
        $this->exec('INSERT INTO list_sender_rules (list_id, rule_type, value) VALUES (?, ?, ?)', [$listId, $type, $value]);
    }

    /** @param list<mixed> $params */
    private function exec(string $sql, array $params = []): void
    {
        $this->pdo->prepare($sql)->execute($params);
    }

    /** @param list<mixed> $params */
    private function scalar(string $sql, array $params = []): mixed
    {
        $stmt = $this->pdo->prepare($sql);
        $stmt->execute($params);

        return $stmt->fetchColumn();
    }

    /**
     * v_lists as sorted 'address scope max_message_kb' strings.
     *
     * @return list<string>
     */
    private function lists(): array
    {
        return $this->col("SELECT CONCAT(address, ' ', scope, ' ', max_message_kb) FROM v_lists");
    }

    /**
     * v_list_sender_rules as sorted 'address|rule_type|value' strings.
     *
     * @return list<string>
     */
    private function rules(): array
    {
        return $this->col("SELECT CONCAT(address, '|', rule_type, '|', value) FROM v_list_sender_rules");
    }

    /**
     * v_login_roles as sorted 'login role' strings.
     *
     * @return list<string>
     */
    private function loginRoles(): array
    {
        return $this->col("SELECT CONCAT(login, ' ', role) FROM v_login_roles");
    }

    private function deploymentCount(): int
    {
        return (int) $this->scalar('SELECT COUNT(*) FROM deployments');
    }

    /** @param list<mixed> $params */
    private function assertSqlError(int $code, string $sql, array $params = []): void
    {
        try {
            $this->exec($sql, $params);
        } catch (PDOException $e) {
            $this->assertSame($code, $e->errorInfo[1] ?? null, $e->getMessage());

            return;
        }

        $this->fail("Expected MariaDB error $code from: $sql");
    }

    private function kickPayload(): string
    {
        return json_encode(['mailbox_id' => $this->alice], JSON_THROW_ON_ERROR);
    }

    // ---- shape -------------------------------------------------------------------

    public function test_views_expose_exactly_the_documented_columns(): void
    {
        $expected = [
            'v_lists' => ['address', 'list_id', 'scope', 'max_message_kb'],
            'v_list_sender_rules' => ['address', 'rule_type', 'value'],
            'v_login_roles' => ['login', 'role'],
            'v_portal_deployments' => ['id', 'job_type', 'payload', 'requested_by_type', 'requested_by_id'],
        ];

        foreach ($expected as $view => $columns) {
            $actual = $this->pdo->query(
                "SELECT column_name FROM information_schema.columns WHERE table_schema = DATABASE() "
                . "AND table_name = '$view' ORDER BY ordinal_position"
            )->fetchAll(PDO::FETCH_COLUMN);

            $this->assertSame($columns, $actual, $view);
        }
    }

    public function test_identifier_columns_are_ascii_bin(): void
    {
        $rows = $this->pdo->query(
            "SELECT CONCAT(table_name, '.', column_name, ' ', collation_name) FROM information_schema.columns "
            . "WHERE table_schema = DATABASE() AND collation_name IS NOT NULL "
            . "AND ((table_name IN ('v_lists', 'v_list_sender_rules') AND column_name = 'address') "
            . "OR (table_name = 'v_list_sender_rules' AND column_name = 'value') "
            . "OR (table_name = 'v_login_roles' AND column_name IN ('login', 'role')))"
        )->fetchAll(PDO::FETCH_COLUMN);
        sort($rows, SORT_STRING);

        $this->assertSame([
            'v_list_sender_rules.address ascii_bin',
            'v_list_sender_rules.value ascii_bin',
            'v_lists.address ascii_bin',
            'v_login_roles.login ascii_bin',
            'v_login_roles.role ascii_bin',
        ], $rows);
    }

    public function test_portal_view_is_updatable_with_a_cascaded_check_option(): void
    {
        $row = $this->pdo->query(
            "SELECT check_option, is_updatable FROM information_schema.views "
            . "WHERE table_schema = DATABASE() AND table_name = 'v_portal_deployments'"
        )->fetch(PDO::FETCH_NUM);

        $this->assertSame(['CASCADED', 'YES'], $row);
    }

    public function test_migration_can_be_run_again(): void
    {
        $sql = file_get_contents(dirname(__DIR__, 2) . '/migrations/0006_policy_views.sql');
        $this->assertNotFalse($sql);

        $statements = SqlSplitter::split($sql);
        $this->assertNotSame([], $statements);
        foreach ($statements as $statement) {
            $this->pdo->exec($statement);
        }

        $this->assertSame(['big@example.com domain 512', 'team@example.com universal 25600'], $this->lists());
    }

    // ---- v_lists -----------------------------------------------------------------

    public function test_v_lists_limits(): void
    {
        // team has no limit of its own and takes max_message_mb (25) * 1024; big keeps its 512.
        // old (suspended list) and gone (list on a suspended domain) are absent.
        $this->assertSame(['big@example.com domain 512', 'team@example.com universal 25600'], $this->lists());
    }

    public function test_v_lists_gives_the_list_id(): void
    {
        $sql = 'SELECT list_id FROM v_lists WHERE address = ?';

        $this->assertSame($this->team, (int) $this->scalar($sql, ['team@example.com']));
        $this->assertSame($this->big, (int) $this->scalar($sql, ['big@example.com']));
    }

    public function test_v_lists_global_limit_follows_the_setting(): void
    {
        $this->exec("UPDATE settings SET value = '50' WHERE `key` = 'max_message_mb'");

        $this->assertSame(['big@example.com domain 512', 'team@example.com universal 51200'], $this->lists());
    }

    public function test_v_lists_own_limit_beats_the_setting(): void
    {
        $this->exec('UPDATE lists SET max_message_kb = 40000 WHERE id = ?', [$this->big]);

        $this->assertSame(['big@example.com domain 40000', 'team@example.com universal 25600'], $this->lists());
    }

    public function test_v_lists_list_suspension_is_immediate(): void
    {
        $this->exec("UPDATE lists SET status = 'suspended' WHERE id = ?", [$this->team]);
        $this->assertSame(['big@example.com domain 512'], $this->lists());

        $this->exec("UPDATE lists SET status = 'active' WHERE id = ?", [$this->old]);
        $this->exec("UPDATE lists SET status = 'active' WHERE id = ?", [$this->team]);
        $this->assertSame(
            ['big@example.com domain 512', 'old@example.com domain 25600', 'team@example.com universal 25600'],
            $this->lists()
        );
    }

    public function test_v_lists_domain_status_is_immediate(): void
    {
        foreach (['suspended', 'deleting'] as $status) {
            $this->exec('UPDATE domains SET status = ? WHERE id = ?', [$status, $this->example]);
            $this->assertSame([], $this->lists(), "domain $status");
        }

        $this->exec("UPDATE domains SET status = 'active' WHERE id = ?", [$this->example]);
        $this->exec("UPDATE domains SET status = 'active' WHERE id = ?", [$this->other]);
        $this->assertSame(
            ['big@example.com domain 512', 'gone@other.org domain 25600', 'team@example.com universal 25600'],
            $this->lists()
        );
    }

    // ---- v_list_sender_rules -----------------------------------------------------

    public function test_v_list_sender_rules(): void
    {
        $this->assertSame(
            ['any_authenticated|', 'domain|example.com'],
            $this->col(
                "SELECT CONCAT(rule_type, '|', value) FROM v_list_sender_rules WHERE address = ?",
                ['team@example.com']
            )
        );
    }

    public function test_v_list_sender_rules_only_cover_the_lists_of_v_lists(): void
    {
        // Rules of old@ (suspended list) and gone@other.org (suspended domain) are absent.
        $this->assertSame(
            [
                'big@example.com|address|bob@example.com',
                'team@example.com|any_authenticated|',
                'team@example.com|domain|example.com',
            ],
            $this->rules()
        );
    }

    public function test_v_list_sender_rules_follow_list_and_domain_status(): void
    {
        $this->exec("UPDATE lists SET status = 'suspended' WHERE id = ?", [$this->team]);
        $this->assertSame(['big@example.com|address|bob@example.com'], $this->rules());

        $this->exec("UPDATE lists SET status = 'active' WHERE id = ?", [$this->team]);
        $this->exec("UPDATE domains SET status = 'suspended' WHERE id = ?", [$this->example]);
        $this->assertSame([], $this->rules());

        $this->exec("UPDATE domains SET status = 'active' WHERE id = ?", [$this->example]);
        $this->assertCount(3, $this->rules());
    }

    // ---- v_login_roles -----------------------------------------------------------

    public function test_v_login_roles(): void
    {
        // Left out: suspended admin, admin on a suspended mailbox, admin on a mailbox of a
        // suspended domain, and admin without a mailbox.
        $this->assertSame(['alice@example.com super_admin'], $this->loginRoles());
    }

    public function test_v_login_roles_names_the_role_of_each_admin(): void
    {
        $this->admin('carol-admin', 'domain_admin', $this->carol);

        $this->assertSame(
            ['alice@example.com super_admin', 'carol@example.com domain_admin'],
            $this->loginRoles()
        );
    }

    public function test_v_login_roles_admin_status_is_immediate(): void
    {
        $this->exec("UPDATE admins SET status = 'suspended' WHERE username = 'root'");
        $this->assertSame([], $this->loginRoles());

        $this->exec("UPDATE admins SET status = 'active' WHERE username IN ('root', 'sleepy')");
        $this->assertSame(
            ['alice@example.com super_admin', 'carol@example.com domain_admin'],
            $this->loginRoles()
        );
    }

    public function test_v_login_roles_mailbox_status_is_immediate(): void
    {
        foreach (['suspended', 'deleting'] as $status) {
            $this->exec('UPDATE mailboxes SET status = ? WHERE id = ?', [$status, $this->alice]);
            $this->assertSame([], $this->loginRoles(), "mailbox $status");
        }

        $this->exec("UPDATE mailboxes SET status = 'active' WHERE id IN (?, ?)", [$this->alice, $this->bob]);
        $this->assertSame(
            ['alice@example.com super_admin', 'bob@example.com domain_admin'],
            $this->loginRoles()
        );
    }

    public function test_v_login_roles_domain_status_is_immediate(): void
    {
        foreach (['suspended', 'deleting'] as $status) {
            $this->exec('UPDATE domains SET status = ? WHERE id = ?', [$status, $this->example]);
            $this->assertSame([], $this->loginRoles(), "domain $status");
        }

        $this->exec("UPDATE domains SET status = 'active' WHERE id = ?", [$this->other]);
        $this->exec("UPDATE domains SET status = 'active' WHERE id = ?", [$this->example]);
        $this->assertSame(
            ['alice@example.com super_admin', 'erin@other.org domain_admin'],
            $this->loginRoles()
        );
    }

    public function test_v_login_roles_unlinking_a_mailbox_removes_the_row(): void
    {
        $this->exec('UPDATE admins SET mailbox_id = NULL WHERE username = ?', ['root']);

        $this->assertSame([], $this->loginRoles());
    }

    // ---- v_portal_deployments ----------------------------------------------------

    public function test_portal_view_accepts_kick(): void
    {
        $this->exec(self::KICK, ['doveadm_kick', $this->kickPayload(), 'mailbox', $this->alice]);

        $rows = $this->pdo->query(
            'SELECT job_type, payload, status, requested_by_type, requested_by_id, created_at, finished_at, log '
            . 'FROM deployments'
        )->fetchAll(PDO::FETCH_ASSOC);

        $this->assertCount(1, $rows);
        $row = $rows[0];
        $this->assertSame('doveadm_kick', $row['job_type']);
        $this->assertSame('{"mailbox_id":' . $this->alice . '}', $row['payload']);
        $this->assertSame('queued', $row['status']);
        $this->assertSame('mailbox', $row['requested_by_type']);
        $this->assertSame($this->alice, (int) $row['requested_by_id']);
        $this->assertNotNull($row['created_at']);
        $this->assertNull($row['finished_at']);
        $this->assertNull($row['log']);
    }

    /** @return array<string,array{string}> */
    public static function otherJobTypes(): array
    {
        $types = [
            'dkim_generate', 'rspamd_policy', 'quarantine_release', 'quarantine_delete',
            'domain_archive', 'mailbox_archive', 'retention_sweep',
        ];

        return array_combine($types, array_map(static fn (string $t): array => [$t], $types));
    }

    /**
     * @dataProvider otherJobTypes
     */
    public function test_portal_view_rejects_other_jobs(string $jobType): void
    {
        $this->assertSqlError(
            self::CHECK_OPTION_FAILED,
            self::KICK,
            [$jobType, $this->kickPayload(), 'mailbox', $this->alice]
        );
        $this->assertSame(0, $this->deploymentCount());
    }

    /** @return array<string,array{string}> */
    public static function otherRequesters(): array
    {
        return ['admin' => ['admin'], 'system' => ['system']];
    }

    /**
     * @dataProvider otherRequesters
     */
    public function test_portal_view_rejects_other_requesters(string $requester): void
    {
        $this->assertSqlError(
            self::CHECK_OPTION_FAILED,
            self::KICK,
            ['doveadm_kick', $this->kickPayload(), $requester, 1]
        );
        $this->assertSame(0, $this->deploymentCount());
    }

    public function test_portal_view_rejects_a_batch_with_one_bad_row(): void
    {
        $this->assertSqlError(
            self::CHECK_OPTION_FAILED,
            'INSERT INTO v_portal_deployments (job_type, payload, requested_by_type, requested_by_id) VALUES '
            . "('doveadm_kick', '{\"mailbox_id\":1}', 'mailbox', 1), ('retention_sweep', '{}', 'mailbox', 1)"
        );
        $this->assertSame(0, $this->deploymentCount());
    }

    /** @return array<string,array{string}> */
    public static function hiddenColumns(): array
    {
        return [
            'status' => ['status'],
            'log' => ['log'],
            'created_at' => ['created_at'],
            'finished_at' => ['finished_at'],
        ];
    }

    /**
     * The view does not expose the columns that only the job runner writes, so the portal
     * cannot queue a job that is already "applied" or carries a log.
     *
     * @dataProvider hiddenColumns
     */
    public function test_portal_view_cannot_set_runner_columns(string $column): void
    {
        $this->assertSqlError(
            self::UNKNOWN_COLUMN,
            "INSERT INTO v_portal_deployments (job_type, payload, requested_by_type, requested_by_id, $column) "
            . "VALUES ('doveadm_kick', '{}', 'mailbox', 1, NULL)"
        );
        $this->assertSame(0, $this->deploymentCount());
    }

    public function test_portal_view_cannot_turn_a_kick_into_another_job(): void
    {
        $this->exec(self::KICK, ['doveadm_kick', $this->kickPayload(), 'mailbox', $this->alice]);
        $id = (int) $this->pdo->lastInsertId();

        $this->assertSqlError(
            self::CHECK_OPTION_FAILED,
            "UPDATE v_portal_deployments SET job_type = 'dkim_generate' WHERE id = ?",
            [$id]
        );
        $this->assertSqlError(
            self::CHECK_OPTION_FAILED,
            "UPDATE v_portal_deployments SET requested_by_type = 'admin' WHERE id = ?",
            [$id]
        );
        $this->assertSame(
            ['doveadm_kick mailbox'],
            $this->col("SELECT CONCAT(job_type, ' ', requested_by_type) FROM deployments WHERE id = ?", [$id])
        );
    }

    public function test_portal_view_shows_only_kicks_requested_by_mailboxes(): void
    {
        $this->exec(self::KICK, ['doveadm_kick', $this->kickPayload(), 'mailbox', $this->alice]);
        $this->exec(
            "INSERT INTO deployments (job_type, payload, requested_by_type, requested_by_id) "
            . "VALUES ('dkim_generate', '{\"domain_id\":1}', 'admin', 1), ('doveadm_kick', '{}', 'system', NULL)"
        );

        $this->assertSame(3, $this->deploymentCount());
        $this->assertSame(
            ['doveadm_kick mailbox'],
            $this->col("SELECT CONCAT(job_type, ' ', requested_by_type) FROM v_portal_deployments")
        );
    }
}
