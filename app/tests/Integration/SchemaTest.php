<?php

declare(strict_types=1);

namespace Mailhost\Tests\Integration;

use PDO;
use PDOException;
use PDOStatement;

/**
 * The 23 base tables of migrations 0001 to 0004: constraints, cascades and seed data.
 *
 * Constraint failures are asserted on MariaDB's error number (PDOException::errorInfo[1]),
 * never on the message: 4025 for a failed CHECK, 1062 for a duplicate key and 1451 for a
 * blocked delete.
 */
final class SchemaTest extends DbTestCase
{
    private const CHECK_FAILED = 4025;
    private const DUPLICATE_KEY = 1062;
    private const ROW_IS_REFERENCED = 1451;

    private const HASH_ARGON = '$argon2id$v=19$m=65536,t=4,p=1$x$y';
    private const HASH_BCRYPT = '$2y$10$abc';

    private const TABLES = [
        'admin_domains',
        'admins',
        'alias_targets',
        'aliases',
        'audit_log',
        'deployments',
        'dkim_keys',
        'domain_aliases',
        'domains',
        'filter_global',
        'filter_policies',
        'forwarding_rules',
        'list_members',
        'list_owners',
        'list_sender_rules',
        'lists',
        'mailboxes',
        'otp_codes',
        'quarantine_items',
        'role_permissions',
        'roles',
        'sessions',
        'settings',
    ];

    private PDO $pdo;

    protected function setUp(): void
    {
        parent::setUp();

        $this->freshDatabase();
        $this->migrateAll();
        $this->pdo = $this->rootPdo();
    }

    // ---- helpers -----------------------------------------------------------------

    /** @param list<mixed> $params */
    private function query(string $sql, array $params = []): PDOStatement
    {
        $stmt = $this->pdo->prepare($sql);
        $stmt->execute($params);

        return $stmt;
    }

    /** @param list<mixed> $params */
    private function scalar(string $sql, array $params = []): mixed
    {
        return $this->query($sql, $params)->fetchColumn();
    }

    /** @param list<mixed> $params */
    private function insertId(string $sql, array $params = []): int
    {
        $this->query($sql, $params);

        return (int) $this->pdo->lastInsertId();
    }

    /** @param list<mixed> $params */
    private function assertSqlError(int $code, string $sql, array $params = []): void
    {
        try {
            $this->query($sql, $params);
        } catch (PDOException $e) {
            $this->assertSame($code, $e->errorInfo[1] ?? null, $e->getMessage());

            return;
        }

        $this->fail("Expected MariaDB error $code from: $sql");
    }

    private function domain(string $name): int
    {
        return $this->insertId('INSERT INTO domains (name) VALUES (?)', [$name]);
    }

    private function mailbox(int $domainId, string $localPart, string $hash = self::HASH_ARGON): int
    {
        return $this->insertId(
            'INSERT INTO mailboxes (domain_id, local_part, password_hash) VALUES (?, ?, ?)',
            [$domainId, $localPart, $hash]
        );
    }

    private function mailList(int $domainId, string $localPart, string $scope = 'domain'): int
    {
        return $this->insertId(
            'INSERT INTO lists (domain_id, local_part, scope) VALUES (?, ?, ?)',
            [$domainId, $localPart, $scope]
        );
    }

    private function admin(string $username, string $role = 'domain_admin', ?int $mailboxId = null): int
    {
        return $this->insertId(
            'INSERT INTO admins (username, email, password_hash, role_id, mailbox_id) '
            . 'VALUES (?, ?, ?, (SELECT id FROM roles WHERE name = ?), ?)',
            [$username, $username . '@example.com', self::HASH_ARGON, $role, $mailboxId]
        );
    }

    // ---- tests -------------------------------------------------------------------

    public function test_all_base_tables_exist(): void
    {
        $names = $this->pdo->query(
            "SELECT table_name FROM information_schema.tables WHERE table_schema = DATABASE() "
            . "AND table_type = 'BASE TABLE' AND table_name <> 'schema_migrations'"
        )->fetchAll(PDO::FETCH_COLUMN);
        sort($names);

        $this->assertCount(23, self::TABLES);
        $this->assertSame(self::TABLES, $names);
    }

    public function test_identifiers_must_be_lowercase(): void
    {
        $this->assertSqlError(self::CHECK_FAILED, 'INSERT INTO domains (name) VALUES (?)', ['Example.com']);

        $domainId = $this->domain('example.com');
        $this->assertSqlError(
            self::CHECK_FAILED,
            'INSERT INTO mailboxes (domain_id, local_part, password_hash) VALUES (?, ?, ?)',
            [$domainId, 'Bob', self::HASH_ARGON]
        );
    }

    public function test_password_hash_prefix_enforced(): void
    {
        $domainId = $this->domain('example.com');

        $this->assertSqlError(
            self::CHECK_FAILED,
            'INSERT INTO mailboxes (domain_id, local_part, password_hash) VALUES (?, ?, ?)',
            [$domainId, 'plain', 'plain']
        );

        $this->mailbox($domainId, 'argon', self::HASH_ARGON);
        $this->mailbox($domainId, 'bcrypt', self::HASH_BCRYPT);

        $this->assertSame(2, (int) $this->scalar('SELECT COUNT(*) FROM mailboxes'));
    }

    public function test_duplicate_mailbox_rejected(): void
    {
        $domainId = $this->domain('example.com');
        $this->mailbox($domainId, 'alice');

        $this->assertSqlError(
            self::DUPLICATE_KEY,
            'INSERT INTO mailboxes (domain_id, local_part, password_hash) VALUES (?, ?, ?)',
            [$domainId, 'alice', self::HASH_ARGON]
        );
    }

    public function test_deleting_domain_cascades(): void
    {
        $a = $this->domain('a.example');
        $b = $this->domain('b.example');

        $mailbox = $this->mailbox($a, 'user');
        $alias = $this->insertId('INSERT INTO aliases (domain_id, local_part) VALUES (?, ?)', [$a, 'sales']);
        $this->query('INSERT INTO alias_targets (alias_id, destination) VALUES (?, ?)', [$alias, 'user@a.example']);
        $this->query(
            'INSERT INTO forwarding_rules (mailbox_id, destination, created_by_type, created_by_id) VALUES (?, ?, ?, ?)',
            [$mailbox, 'user@gmail.com', 'admin', 1]
        );
        $this->query('INSERT INTO domain_aliases (alias_domain, target_domain_id) VALUES (?, ?)', ['a-alias.example', $a]);
        $this->query('INSERT INTO dkim_keys (domain_id, selector, public_key) VALUES (?, ?, ?)', [$a, 'mail', 'KEY']);

        $domainList = $this->mailList($a, 'news');
        $this->query('INSERT INTO list_members (list_id, mailbox_id) VALUES (?, ?)', [$domainList, $mailbox]);
        $this->query('INSERT INTO list_owners (list_id, mailbox_id) VALUES (?, ?)', [$domainList, $mailbox]);
        $this->query(
            'INSERT INTO list_sender_rules (list_id, rule_type, value) VALUES (?, ?, ?)',
            [$domainList, 'address', 'boss@a.example']
        );

        $universal = $this->mailList($b, 'everyone', 'universal');
        $this->query('INSERT INTO list_members (list_id, mailbox_id) VALUES (?, ?)', [$universal, $mailbox]);

        $admin = $this->admin('dave');
        $this->query('INSERT INTO admin_domains (admin_id, domain_id) VALUES (?, ?)', [$admin, $a]);
        $this->query(
            'INSERT INTO filter_policies (domain_id, tag_score, quarantine_score, reject_score) VALUES (?, 5, 9, 14)',
            [$a]
        );
        $this->query(
            'INSERT INTO quarantine_items (queue_id, domain_id, envelope_from, envelope_to, score, reason, size_bytes) '
            . 'VALUES (?, ?, ?, ?, ?, ?, ?)',
            ['Q1', $a, 'spam@evil.test', 'user@a.example', 11.5, 'BAYES_SPAM', 1234]
        );
        $this->query(
            'INSERT INTO audit_log (actor_type, action, domain_id) VALUES (?, ?, ?)',
            ['admin', 'domain.delete', $a]
        );

        $this->query('DELETE FROM domains WHERE id = ?', [$a]);

        $gone = [
            'domain_aliases' => ['SELECT COUNT(*) FROM domain_aliases WHERE target_domain_id = ?', $a],
            'dkim_keys' => ['SELECT COUNT(*) FROM dkim_keys WHERE domain_id = ?', $a],
            'mailboxes' => ['SELECT COUNT(*) FROM mailboxes WHERE domain_id = ?', $a],
            'aliases' => ['SELECT COUNT(*) FROM aliases WHERE domain_id = ?', $a],
            'alias_targets' => ['SELECT COUNT(*) FROM alias_targets WHERE alias_id = ?', $alias],
            'forwarding_rules' => ['SELECT COUNT(*) FROM forwarding_rules WHERE mailbox_id = ?', $mailbox],
            'lists' => ['SELECT COUNT(*) FROM lists WHERE domain_id = ?', $a],
            'list_members of the domain list' => ['SELECT COUNT(*) FROM list_members WHERE list_id = ?', $domainList],
            'list_members of the mailbox' => ['SELECT COUNT(*) FROM list_members WHERE mailbox_id = ?', $mailbox],
            'list_owners' => ['SELECT COUNT(*) FROM list_owners WHERE list_id = ?', $domainList],
            'list_sender_rules' => ['SELECT COUNT(*) FROM list_sender_rules WHERE list_id = ?', $domainList],
            'admin_domains' => ['SELECT COUNT(*) FROM admin_domains WHERE domain_id = ?', $a],
            'filter_policies' => ['SELECT COUNT(*) FROM filter_policies WHERE domain_id = ?', $a],
            'quarantine_items' => ['SELECT COUNT(*) FROM quarantine_items WHERE domain_id = ?', $a],
        ];
        foreach ($gone as $label => [$sql, $id]) {
            $this->assertSame(0, (int) $this->scalar($sql, [$id]), "$label should be empty after the delete");
        }

        // The universal list of the other domain survives, minus the deleted mailbox.
        $this->assertSame(1, (int) $this->scalar('SELECT COUNT(*) FROM lists WHERE id = ?', [$universal]));
        $this->assertSame(0, (int) $this->scalar('SELECT COUNT(*) FROM list_members WHERE list_id = ?', [$universal]));
        $this->assertSame(1, (int) $this->scalar('SELECT COUNT(*) FROM domains WHERE id = ?', [$b]));

        // Admins belong to no domain, and the audit history has no foreign key.
        $this->assertSame(1, (int) $this->scalar('SELECT COUNT(*) FROM admins WHERE id = ?', [$admin]));
        $this->assertSame(1, (int) $this->scalar('SELECT COUNT(*) FROM audit_log WHERE domain_id = ?', [$a]));
    }

    public function test_admin_mailbox_link_set_null(): void
    {
        $domainId = $this->domain('example.com');
        $mailbox = $this->mailbox($domainId, 'root');
        $admin = $this->admin('rootadmin', 'super_admin', $mailbox);

        $this->assertSame($mailbox, (int) $this->scalar('SELECT mailbox_id FROM admins WHERE id = ?', [$admin]));

        $this->query('DELETE FROM mailboxes WHERE id = ?', [$mailbox]);

        $this->assertSame(1, (int) $this->scalar('SELECT COUNT(*) FROM admins WHERE id = ?', [$admin]));
        $this->assertNull($this->scalar('SELECT mailbox_id FROM admins WHERE id = ?', [$admin]));
    }

    public function test_role_in_use_cannot_be_deleted(): void
    {
        $this->admin('someone', 'domain_admin');

        $this->assertSqlError(self::ROW_IS_REFERENCED, "DELETE FROM roles WHERE name = 'domain_admin'");
    }

    public function test_filter_policy_rules(): void
    {
        // The global policy is a single row with id 1.
        $this->assertSqlError(
            self::CHECK_FAILED,
            'INSERT INTO filter_global (id, tag_score, quarantine_score, reject_score, bound_min_score, bound_max_score) '
            . 'VALUES (2, 6, 10, 15, 4, 25)'
        );

        // One policy row per domain.
        $domainId = $this->domain('example.com');
        $insert = 'INSERT INTO filter_policies (domain_id, tag_score, quarantine_score, reject_score) VALUES (?, ?, ?, ?)';
        $this->query($insert, [$domainId, 5, 9, 14]);
        $this->assertSqlError(self::DUPLICATE_KEY, $insert, [$domainId, 5, 9, 14]);

        // Thresholds must not decrease: tag <= quarantine <= reject.
        $other = $this->domain('other.org');
        $this->assertSqlError(self::CHECK_FAILED, $insert, [$other, 16, 10, 15]);
        $this->assertSqlError(self::CHECK_FAILED, $insert, [$other, 6, 16, 15]);
        $this->assertSqlError(self::CHECK_FAILED, 'UPDATE filter_global SET tag_score = 16');
        $this->assertSqlError(self::CHECK_FAILED, 'UPDATE filter_global SET quarantine_score = 16');
        $this->assertSqlError(self::CHECK_FAILED, 'UPDATE filter_policies SET tag_score = 16');

        // Equal thresholds are allowed, and the global bounds must be ordered.
        $this->query($insert, [$other, 8, 8, 8]);
        $this->assertSqlError(self::CHECK_FAILED, 'UPDATE filter_global SET bound_min_score = 26');
    }

    public function test_sender_rule_value_rules(): void
    {
        $list = $this->mailList($this->domain('example.com'), 'team');
        $insert = 'INSERT INTO list_sender_rules (list_id, rule_type, value) VALUES (?, ?, ?)';

        $this->assertSqlError(self::CHECK_FAILED, $insert, [$list, 'any_authenticated', 'x']);
        $this->assertSqlError(self::CHECK_FAILED, $insert, [$list, 'address', '']);

        $this->query($insert, [$list, 'any_authenticated', '']);
        $this->query($insert, [$list, 'address', 'boss@example.com']);
        $this->assertSqlError(self::DUPLICATE_KEY, $insert, [$list, 'address', 'boss@example.com']);
    }

    /**
     * @dataProvider badValues
     *
     * @param list<mixed> $params
     */
    public function test_format_checks_reject_bad_values(string $sql, array $params): void
    {
        $domainId = $this->domain('example.com');
        $this->mailbox($domainId, 'alice');
        $alias = $this->insertId('INSERT INTO aliases (domain_id, local_part) VALUES (?, ?)', [$domainId, 'sales']);
        $this->mailList($domainId, 'staff');
        $this->assertGreaterThan(0, $alias);

        $this->assertSqlError(self::CHECK_FAILED, $sql, $params);
    }

    /** @return array<string,array{string,list<mixed>}> */
    public function badValues(): array
    {
        $domain = "(SELECT id FROM domains WHERE name = 'example.com')";
        $mailbox = "(SELECT id FROM mailboxes WHERE local_part = 'alice')";
        $alias = "(SELECT id FROM aliases WHERE local_part = 'sales')";
        $list = "(SELECT id FROM lists WHERE local_part = 'staff')";
        $admin = 'INSERT INTO admins (username, email, password_hash, role_id) '
            . "VALUES (?, ?, ?, (SELECT id FROM roles WHERE name = 'domain_admin'))";

        return [
            'domain with an underscore' => ['INSERT INTO domains (name) VALUES (?)', ['bad_name.com']],
            'domain starting with a hyphen' => ['INSERT INTO domains (name) VALUES (?)', ['-bad.com']],
            'domain ending with a dot' => ['INSERT INTO domains (name) VALUES (?)', ['bad.com.']],
            'alias domain in uppercase' => [
                "INSERT INTO domain_aliases (alias_domain, target_domain_id) VALUES (?, $domain)",
                ['Alias.net'],
            ],
            'dkim selector in uppercase' => [
                "INSERT INTO dkim_keys (domain_id, selector, public_key) VALUES ($domain, ?, 'KEY')",
                ['Mail'],
            ],
            'dkim selector with an underscore' => [
                "INSERT INTO dkim_keys (domain_id, selector, public_key) VALUES ($domain, ?, 'KEY')",
                ['mail_1'],
            ],
            'mailbox local part with a space' => [
                "INSERT INTO mailboxes (domain_id, local_part, password_hash) VALUES ($domain, ?, '\$2y\$10\$abc')",
                ['a b'],
            ],
            'mailbox local part empty' => [
                "INSERT INTO mailboxes (domain_id, local_part, password_hash) VALUES ($domain, ?, '\$2y\$10\$abc')",
                [''],
            ],
            'recovery email in uppercase' => [
                "INSERT INTO mailboxes (domain_id, local_part, password_hash, recovery_email) "
                . "VALUES ($domain, 'carol', '\$2y\$10\$abc', ?)",
                ['Carol@Example.com'],
            ],
            'alias local part in uppercase' => [
                "INSERT INTO aliases (domain_id, local_part) VALUES ($domain, ?)",
                ['Info'],
            ],
            'alias target without an address' => [
                "INSERT INTO alias_targets (alias_id, destination) VALUES ($alias, ?)",
                ['nobody'],
            ],
            'alias target without a domain' => [
                "INSERT INTO alias_targets (alias_id, destination) VALUES ($alias, ?)",
                ['nobody@'],
            ],
            'alias target in uppercase' => [
                "INSERT INTO alias_targets (alias_id, destination) VALUES ($alias, ?)",
                ['Bob@example.com'],
            ],
            'forwarding destination without an address' => [
                "INSERT INTO forwarding_rules (mailbox_id, destination, created_by_type, created_by_id) "
                . "VALUES ($mailbox, ?, 'admin', 1)",
                ['nobody'],
            ],
            'list local part empty' => [
                "INSERT INTO lists (domain_id, local_part, scope) VALUES ($domain, ?, 'domain')",
                [''],
            ],
            'list sender rule value in uppercase' => [
                "INSERT INTO list_sender_rules (list_id, rule_type, value) VALUES ($list, 'address', ?)",
                ['Boss@example.com'],
            ],
            'admin username too short' => [$admin, ['ab', 'ab@example.com', self::HASH_ARGON]],
            'admin username in uppercase' => [$admin, ['Admin1', 'admin1@example.com', self::HASH_ARGON]],
            'admin email in uppercase' => [$admin, ['admin1', 'Admin1@Example.com', self::HASH_ARGON]],
            'admin password hash not hashed' => [$admin, ['admin1', 'admin1@example.com', 'secret']],
            'otp target in uppercase' => [
                "INSERT INTO otp_codes (subject_type, subject_id, purpose, code_hmac, target, expires_at, request_ip) "
                . "VALUES ('mailbox', 1, 'verify_email', REPEAT('a', 64), ?, UTC_TIMESTAMP(), '127.0.0.1')",
                ['New@Example.com'],
            ],
        ];
    }

    public function test_seeds(): void
    {
        $permissions = [];
        $rows = $this->pdo->query(
            'SELECT r.name AS role, rp.permission FROM roles r JOIN role_permissions rp ON rp.role_id = r.id'
        )->fetchAll();
        foreach ($rows as $row) {
            $permissions[$row['role']][] = $row['permission'];
        }
        ksort($permissions);
        array_walk($permissions, static function (array &$list): void {
            sort($list);
        });

        $superAdmin = [
            'domain.manage', 'domain.view', 'mailbox.manage', 'alias.manage', 'forwarding.manage',
            'list.domain.manage', 'list.universal.manage', 'filter.global.manage', 'filter.domain.manage',
            'quarantine.manage', 'admin.manage', 'audit.read', 'system.configure',
        ];
        $domainAdmin = [
            'domain.view', 'mailbox.manage', 'alias.manage', 'forwarding.manage',
            'list.domain.manage', 'filter.domain.manage', 'audit.read',
        ];
        sort($superAdmin);
        sort($domainAdmin);

        $this->assertSame(['domain_admin' => $domainAdmin, 'super_admin' => $superAdmin], $permissions);
        $this->assertSame(
            ['domain_admin', 'super_admin'],
            $this->pdo->query('SELECT name FROM roles ORDER BY name')->fetchAll(PDO::FETCH_COLUMN)
        );

        $settings = $this->pdo->query('SELECT `key`, value FROM settings ORDER BY `key`')->fetchAll(PDO::FETCH_KEY_PAIR);
        $expected = [
            'otp_ttl_minutes' => '10',
            'otp_max_attempts' => '5',
            'external_forwarding' => 'allow',
            'superadmin_list_override' => 'allow',
            'retention_suspended_days' => '30',
            'retention_archive_days' => '90',
            'max_message_mb' => '25',
        ];
        ksort($expected);
        $this->assertSame($expected, $settings);

        $global = $this->pdo->query('SELECT * FROM filter_global')->fetchAll();
        $this->assertCount(1, $global);
        $this->assertEquals(
            [
                'id' => 1,
                'tag_score' => '6.00',
                'quarantine_score' => '10.00',
                'reject_score' => '15.00',
                'virus_action' => 'reject',
                'unscannable_action' => 'quarantine',
                'bound_min_score' => '4.00',
                'bound_max_score' => '25.00',
            ],
            $global[0]
        );
    }

    public function test_migrations_rerunnable(): void
    {
        $this->pdo->exec('DELETE FROM schema_migrations');

        $this->migrateAll();

        $this->assertSame(20, (int) $this->scalar('SELECT COUNT(*) FROM role_permissions'));
        $this->assertSame(2, (int) $this->scalar('SELECT COUNT(*) FROM roles'));
        $this->assertSame(7, (int) $this->scalar('SELECT COUNT(*) FROM settings'));
        $this->assertSame(1, (int) $this->scalar('SELECT COUNT(*) FROM filter_global'));
        $this->assertSame(
            ['0001_core_tables', '0002_lists', '0003_rbac', '0004_ops'],
            $this->pdo->query('SELECT version FROM schema_migrations ORDER BY version')->fetchAll(PDO::FETCH_COLUMN)
        );
    }
}
