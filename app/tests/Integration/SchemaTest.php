<?php

declare(strict_types=1);

namespace Mailhost\Tests\Integration;

use PDO;
use PDOException;
use PDOStatement;

/**
 * The base tables of migrations 0001 to 0004 and 0007 to 0012: constraints, cascades and seed data.
 *
 * Constraint failures are asserted on MariaDB's error number (PDOException::errorInfo[1]):
 * 4025 for a failed CHECK, 1062 for a duplicate key and 1451 for a blocked delete. For a
 * failed CHECK the test also names the constraint it expects, because a column with several
 * checks (lowercase, format, not empty) fails on the first one MariaDB evaluates, and only the
 * name shows which rule caught the value.
 */
final class SchemaTest extends DbTestCase
{
    use Fixtures;

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
        'app_passwords',
        'audit_log',
        'delivery_events',
        'deployments',
        'dkim_keys',
        'dmarc_records',
        'dmarc_reports',
        'domain_aliases',
        'domain_checks',
        'domains',
        'filter_global',
        'filter_policies',
        'forwarding_rules',
        'list_members',
        'list_owners',
        'list_sender_rules',
        'lists',
        'log_cursors',
        'login_events',
        'mailboxes',
        'migration_jobs',
        'otp_codes',
        'quarantine_items',
        'quota_requests',
        'recovery_codes',
        'release_requests',
        'role_permissions',
        'roles',
        'sessions',
        'settings',
        'shared_access',
        'sieve_rules',
        'spam_sender_lists',
        'totp_secrets',
        'vacation_settings',
    ];

    protected function setUp(): void
    {
        parent::setUp();

        $this->freshDatabase();
        $this->migrateAll();
    }

    // ---- helpers -----------------------------------------------------------------

    /** @param list<mixed> $params */
    private function query(string $sql, array $params = []): PDOStatement
    {
        $stmt = $this->pdo()->prepare($sql);
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

        return (int) $this->pdo()->lastInsertId();
    }

    /**
     * Asserts that $sql fails with MariaDB error $code and, when $constraint is given, that the
     * error names that CHECK constraint ("CONSTRAINT `chk_x` failed for ...").
     *
     * @param list<mixed> $params
     */
    private function assertSqlError(int $code, string $sql, array $params = [], ?string $constraint = null): void
    {
        try {
            $this->query($sql, $params);
        } catch (PDOException $e) {
            $this->assertSame($code, $e->errorInfo[1] ?? null, $e->getMessage());
            if ($constraint !== null) {
                $this->assertStringContainsString("CONSTRAINT `$constraint` failed", $e->getMessage());
            }

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
        $names = $this->pdo()->query(
            "SELECT table_name FROM information_schema.tables WHERE table_schema = DATABASE() "
            . "AND table_type = 'BASE TABLE' AND table_name <> 'schema_migrations'"
        )->fetchAll(PDO::FETCH_COLUMN);
        sort($names);

        $this->assertCount(39, self::TABLES);
        $this->assertSame(self::TABLES, $names);
    }

    public function test_identifiers_must_be_lowercase(): void
    {
        $this->assertSqlError(
            self::CHECK_FAILED,
            'INSERT INTO domains (name) VALUES (?)',
            ['Example.com'],
            'chk_domains_name_lc'
        );

        $domainId = $this->domain('example.com');
        $this->assertSqlError(
            self::CHECK_FAILED,
            'INSERT INTO mailboxes (domain_id, local_part, password_hash) VALUES (?, ?, ?)',
            [$domainId, 'Bob', self::HASH_ARGON],
            'chk_mailboxes_local_part_lc'
        );
    }

    public function test_password_hash_prefix_enforced(): void
    {
        $domainId = $this->domain('example.com');

        $this->assertSqlError(
            self::CHECK_FAILED,
            'INSERT INTO mailboxes (domain_id, local_part, password_hash) VALUES (?, ?, ?)',
            [$domainId, 'plain', 'plain'],
            'chk_mailboxes_password_hash_prefix'
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
            . 'VALUES (2, 6, 10, 15, 4, 25)',
            [],
            'chk_filter_global_single_row'
        );

        // One policy row per domain.
        $domainId = $this->domain('example.com');
        $insert = 'INSERT INTO filter_policies (domain_id, tag_score, quarantine_score, reject_score) VALUES (?, ?, ?, ?)';
        $this->query($insert, [$domainId, 5, 9, 14]);
        $this->assertSqlError(self::DUPLICATE_KEY, $insert, [$domainId, 5, 9, 14]);

        // Thresholds must not decrease: tag <= quarantine <= reject.
        $other = $this->domain('other.org');
        $this->assertSqlError(self::CHECK_FAILED, $insert, [$other, 16, 10, 15], 'chk_filter_policies_scores_ordered');
        $this->assertSqlError(self::CHECK_FAILED, $insert, [$other, 6, 16, 15], 'chk_filter_policies_scores_ordered');
        $this->assertSqlError(self::CHECK_FAILED, 'UPDATE filter_global SET tag_score = 16', [], 'chk_filter_global_scores_ordered');
        $this->assertSqlError(
            self::CHECK_FAILED,
            'UPDATE filter_global SET quarantine_score = 16',
            [],
            'chk_filter_global_scores_ordered'
        );
        $this->assertSqlError(self::CHECK_FAILED, 'UPDATE filter_policies SET tag_score = 16', [], 'chk_filter_policies_scores_ordered');

        // Equal thresholds are allowed, and the global bounds must be ordered.
        $this->query($insert, [$other, 8, 8, 8]);
        $this->assertSqlError(
            self::CHECK_FAILED,
            'UPDATE filter_global SET bound_min_score = 26',
            [],
            'chk_filter_global_bounds_ordered'
        );
    }

    public function test_sender_rule_value_rules(): void
    {
        $list = $this->mailList($this->domain('example.com'), 'team');
        $insert = 'INSERT INTO list_sender_rules (list_id, rule_type, value) VALUES (?, ?, ?)';

        $this->assertSqlError(self::CHECK_FAILED, $insert, [$list, 'any_authenticated', 'x'], 'chk_list_sender_rules_value_by_type');
        $this->assertSqlError(self::CHECK_FAILED, $insert, [$list, 'address', ''], 'chk_list_sender_rules_value_by_type');

        $this->query($insert, [$list, 'any_authenticated', '']);
        $this->query($insert, [$list, 'address', 'boss@example.com']);
        $this->query($insert, [$list, 'domain', 'example.com']);
        $this->query($insert, [$list, 'role', 'super_admin']);
        $this->assertSqlError(self::DUPLICATE_KEY, $insert, [$list, 'address', 'boss@example.com']);
    }

    /**
     * @dataProvider badValues
     *
     * @param list<mixed> $params
     */
    public function test_format_checks_reject_bad_values(string $sql, array $params, string $constraint): void
    {
        $domainId = $this->domain('example.com');
        $this->mailbox($domainId, 'alice');
        $this->insertId('INSERT INTO aliases (domain_id, local_part) VALUES (?, ?)', [$domainId, 'sales']);
        $this->mailList($domainId, 'staff');

        $this->assertSqlError(self::CHECK_FAILED, $sql, $params, $constraint);
    }

    /**
     * Each case: the statement, its parameters and the CHECK constraint that must reject it.
     *
     * @return array<string,array{string,list<mixed>,string}>
     */
    public function badValues(): array
    {
        $domain = "(SELECT id FROM domains WHERE name = 'example.com')";
        $mailbox = "(SELECT id FROM mailboxes WHERE local_part = 'alice')";
        $alias = "(SELECT id FROM aliases WHERE local_part = 'sales')";
        $list = "(SELECT id FROM lists WHERE local_part = 'staff')";
        $admin = 'INSERT INTO admins (username, email, password_hash, role_id) '
            . "VALUES (?, ?, ?, (SELECT id FROM roles WHERE name = 'domain_admin'))";

        $insertDomain = 'INSERT INTO domains (name) VALUES (?)';
        $insertAliasDomain = "INSERT INTO domain_aliases (alias_domain, target_domain_id) VALUES (?, $domain)";
        $insertMailbox = "INSERT INTO mailboxes (domain_id, local_part, password_hash) VALUES ($domain, ?, '\$2y\$10\$abc')";
        $insertRecovery = 'INSERT INTO mailboxes (domain_id, local_part, password_hash, recovery_email) '
            . "VALUES ($domain, 'carol', '\$2y\$10\$abc', ?)";
        $insertAlias = "INSERT INTO aliases (domain_id, local_part) VALUES ($domain, ?)";
        $insertTarget = "INSERT INTO alias_targets (alias_id, destination) VALUES ($alias, ?)";
        $insertForward = 'INSERT INTO forwarding_rules (mailbox_id, destination, created_by_type, created_by_id) '
            . "VALUES ($mailbox, ?, 'admin', 1)";
        $insertList = "INSERT INTO lists (domain_id, local_part, scope) VALUES ($domain, ?, 'domain')";
        $insertRule = "INSERT INTO list_sender_rules (list_id, rule_type, value) VALUES ($list, ?, ?)";
        $ruleFormat = 'chk_list_sender_rules_value_format';
        $insertOtpTarget = 'INSERT INTO otp_codes (subject_type, subject_id, purpose, code_hmac, target, expires_at, request_ip) '
            . "VALUES ('mailbox', 1, 'verify_email', REPEAT('a', 64), ?, UTC_TIMESTAMP(), '127.0.0.1')";

        $cases = [
            'domain with an underscore' => [$insertDomain, ['bad_name.com'], 'chk_domains_name_format'],
            'domain starting with a hyphen' => [$insertDomain, ['-bad.com'], 'chk_domains_name_format'],
            'domain ending with a dot' => [$insertDomain, ['bad.com.'], 'chk_domains_name_format'],
            'domain with a trailing newline' => [$insertDomain, ["example.com\n"], 'chk_domains_name_format'],
            'alias domain in uppercase' => [$insertAliasDomain, ['Alias.net'], 'chk_domain_aliases_alias_domain_lc'],
            'dkim selector in uppercase' => [
                "INSERT INTO dkim_keys (domain_id, selector, public_key) VALUES ($domain, ?, 'KEY')",
                ['Mail'],
                'chk_dkim_keys_selector_lc',
            ],
            'dkim selector with an underscore' => [
                "INSERT INTO dkim_keys (domain_id, selector, public_key) VALUES ($domain, ?, 'KEY')",
                ['mail_1'],
                'chk_dkim_keys_selector_format',
            ],
            'dkim selector with a trailing newline' => [
                "INSERT INTO dkim_keys (domain_id, selector, public_key) VALUES ($domain, ?, 'KEY')",
                ["mail\n"],
                'chk_dkim_keys_selector_format',
            ],
            'mailbox local part with a space' => [$insertMailbox, ['a b'], 'chk_mailboxes_local_part_format'],
            'mailbox local part with a trailing newline' => [$insertMailbox, ["alice\n"], 'chk_mailboxes_local_part_format'],
            'mailbox local part empty' => [$insertMailbox, [''], 'chk_mailboxes_local_part_format'],
            'recovery email in uppercase' => [$insertRecovery, ['Carol@Example.com'], 'chk_mailboxes_recovery_email_lc'],
            'alias local part in uppercase' => [$insertAlias, ['Info'], 'chk_aliases_local_part_lc'],
            'alias target without an address' => [$insertTarget, ['nobody'], 'chk_alias_targets_destination_format'],
            'alias target without a domain' => [$insertTarget, ['nobody@'], 'chk_alias_targets_destination_format'],
            'alias target in uppercase' => [$insertTarget, ['Bob@example.com'], 'chk_alias_targets_destination_lc'],
            'forwarding destination without an address' => [$insertForward, ['nobody'], 'chk_forwarding_rules_destination_format'],
            'forwarding destination in uppercase' => [$insertForward, ['Carol@Example.com'], 'chk_forwarding_rules_destination_lc'],
            'list local part empty' => [$insertList, [''], 'chk_lists_local_part_not_empty'],
            'list local part in uppercase' => [$insertList, ['Staff2'], 'chk_lists_local_part_lc'],
            'list sender rule value in uppercase' => [$insertRule, ['address', 'Boss@example.com'], 'chk_list_sender_rules_value_lc'],
            'list sender rule address with a comma' => [$insertRule, ['address', 'boss@example.com,all@example.com'], $ruleFormat],
            'list sender rule address that is a domain' => [$insertRule, ['address', 'example.com'], $ruleFormat],
            'list sender rule domain that is an address' => [$insertRule, ['domain', 'boss@example.com'], $ruleFormat],
            'list sender rule domain with one label' => [$insertRule, ['domain', 'localhost'], $ruleFormat],
            'list sender rule role with a space' => [$insertRule, ['role', 'super admin'], $ruleFormat],
            'list sender rule role with a trailing newline' => [$insertRule, ['role', "super_admin\n"], $ruleFormat],
            'admin username too short' => [$admin, ['ab', 'ab@example.com', self::HASH_ARGON], 'chk_admins_username_format'],
            'admin username in uppercase' => [$admin, ['Admin1', 'admin1@example.com', self::HASH_ARGON], 'chk_admins_username_format'],
            'admin username with a trailing newline' => [
                $admin,
                ["admin1\n", 'admin1@example.com', self::HASH_ARGON],
                'chk_admins_username_format',
            ],
            'admin email in uppercase' => [$admin, ['admin1', 'Admin1@Example.com', self::HASH_ARGON], 'chk_admins_email_lc'],
            'admin password hash not hashed' => [$admin, ['admin1', 'admin1@example.com', 'secret'], 'chk_admins_password_hash_prefix'],
            'otp code hmac in uppercase hex' => [
                'INSERT INTO otp_codes (subject_type, subject_id, purpose, code_hmac, expires_at, request_ip) '
                . "VALUES ('mailbox', 1, 'login', ?, UTC_TIMESTAMP(), '127.0.0.1')",
                [str_repeat('A', 64)],
                'chk_otp_codes_code_hmac_lc',
            ],
            'session token hash in uppercase hex' => [
                'INSERT INTO sessions (token_hash, subject_type, subject_id, expires_at, ip, user_agent) '
                . "VALUES (?, 'admin', 1, UTC_TIMESTAMP(), '127.0.0.1', 'test')",
                [str_repeat('A', 64)],
                'chk_sessions_token_hash_lc',
            ],
            'otp target in uppercase' => [$insertOtpTarget, ['New@Example.com'], 'chk_otp_codes_target_lc'],
        ];

        // Dots only between atoms: "." and ".." would make the maildir domain/local_part/
        // climb out of the domain directory.
        $badLocalParts = ['..', '.', 'a.', '.a', 'a..b'];
        $localPartColumns = [
            'mailbox' => [$insertMailbox, 'chk_mailboxes_local_part_format'],
            'alias' => [$insertAlias, 'chk_aliases_local_part_format'],
            'list' => [$insertList, 'chk_lists_local_part_format'],
        ];
        foreach ($localPartColumns as $label => [$sql, $constraint]) {
            foreach ($badLocalParts as $value) {
                $cases["$label local part \"$value\""] = [$sql, [$value], $constraint];
            }
        }

        // Exactly one @ and nothing Postfix or a mail header would read as a second address.
        $badAddresses = [
            'a comma' => 'me@gmail.com,all@example.com',
            'a space' => 'a b@x.com',
            'two @' => 'a@b@c.com',
            'quotes' => '"a"@x.com',
            'angle brackets' => '<a@x.com>',
            'a trailing newline' => "a@x.com\n",
        ];
        $addressColumns = [
            'alias target' => [$insertTarget, [], 'chk_alias_targets_destination_format'],
            'forwarding destination' => [$insertForward, [], 'chk_forwarding_rules_destination_format'],
            'recovery email' => [$insertRecovery, [], 'chk_mailboxes_recovery_email_format'],
            'admin email' => [$admin, ['admin1'], 'chk_admins_email_format'],
        ];
        foreach ($addressColumns as $label => [$sql, $before, $constraint]) {
            foreach ($badAddresses as $what => $value) {
                $params = [...$before, $value];
                if ($label === 'admin email') {
                    $params[] = self::HASH_ARGON;
                }
                $cases["$label with $what"] = [$sql, $params, $constraint];
            }
        }
        foreach (['a comma', 'a trailing newline'] as $what) {
            $cases["otp target with $what"] = [$insertOtpTarget, [$badAddresses[$what]], 'chk_otp_codes_target_format'];
        }

        // At least two labels, single dots, no hyphen at either end of a label.
        $badDomains = ['localhost', 'a..b.com', '-a.com'];
        foreach ($badDomains as $value) {
            $cases["domain \"$value\""] = [$insertDomain, [$value], 'chk_domains_name_format'];
            $cases["alias domain \"$value\""] = [$insertAliasDomain, [$value], 'chk_domain_aliases_alias_domain_format'];
        }

        return $cases;
    }

    /**
     * The tightened formats still take the ordinary shapes: plus and dot addressing, hyphens,
     * digits, punycode labels and deep subdomains.
     */
    public function test_format_checks_accept_valid_values(): void
    {
        $domainId = $this->domain('xn--bcher-kva.example');
        $this->domain('mail-1.sub.example.co');
        $this->query('INSERT INTO domain_aliases (alias_domain, target_domain_id) VALUES (?, ?)', ['a-b.c-d.example', $domainId]);

        $mailbox = $this->mailbox($domainId, 'first.last+tag_x-1');
        $this->query('UPDATE mailboxes SET recovery_email = ? WHERE id = ?', ['me+recovery@mail-1.sub.example.co', $mailbox]);
        $alias = $this->insertId('INSERT INTO aliases (domain_id, local_part) VALUES (?, ?)', [$domainId, 'no-reply']);
        $this->query(
            'INSERT INTO alias_targets (alias_id, destination) VALUES (?, ?)',
            [$alias, 'first.last+tag_x-1@xn--bcher-kva.example']
        );
        $this->query(
            'INSERT INTO forwarding_rules (mailbox_id, destination, created_by_type, created_by_id) VALUES (?, ?, ?, ?)',
            [$mailbox, 'a_b@x1.io', 'mailbox', $mailbox]
        );
        $list = $this->mailList($domainId, 'all-staff.2026');
        $insertRule = 'INSERT INTO list_sender_rules (list_id, rule_type, value) VALUES (?, ?, ?)';
        $this->query($insertRule, [$list, 'address', 'boss.one@a-b.c-d.example']);
        $this->query($insertRule, [$list, 'domain', 'mail-1.sub.example.co']);
        $this->query($insertRule, [$list, 'role', 'domain_admin']);
        $this->admin('ops.admin');

        $this->assertSame(
            ['all-staff.2026', 'first.last+tag_x-1', 'no-reply'],
            $this->pdo()->query(
                'SELECT local_part FROM mailboxes UNION SELECT local_part FROM aliases UNION SELECT local_part FROM lists '
                . 'ORDER BY local_part'
            )->fetchAll(PDO::FETCH_COLUMN)
        );
    }

    public function test_catch_all_alias_is_rejected(): void
    {
        $domainId = $this->domain('example.com');

        $this->assertSqlError(
            self::CHECK_FAILED,
            'INSERT INTO aliases (domain_id, local_part) VALUES (?, ?)',
            [$domainId, ''],
            'chk_aliases_local_part_not_empty'
        );
        $this->assertNull($this->scalar(
            "SELECT column_default FROM information_schema.columns WHERE table_schema = DATABASE() "
            . "AND table_name = 'aliases' AND column_name = 'local_part'"
        ));
    }

    public function test_hash_columns_accept_lowercase_hex(): void
    {
        $hex = hash('sha256', 'secret');

        $this->query(
            "INSERT INTO otp_codes (subject_type, subject_id, purpose, code_hmac, expires_at, request_ip) "
            . "VALUES ('mailbox', 1, 'login', ?, UTC_TIMESTAMP(), '127.0.0.1')",
            [$hex]
        );
        $this->query(
            "INSERT INTO sessions (token_hash, subject_type, subject_id, expires_at, ip, user_agent) "
            . "VALUES (?, 'admin', 1, UTC_TIMESTAMP(), '127.0.0.1', 'test')",
            [$hex]
        );

        $this->assertSame($hex, $this->scalar('SELECT code_hmac FROM otp_codes'));
        $this->assertSame($hex, $this->scalar('SELECT token_hash FROM sessions'));
    }

    public function test_seeds(): void
    {
        $permissions = [];
        $rows = $this->pdo()->query(
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
            $this->pdo()->query('SELECT name FROM roles ORDER BY name')->fetchAll(PDO::FETCH_COLUMN)
        );

        $settings = $this->pdo()->query('SELECT `key`, value FROM settings ORDER BY `key`')->fetchAll(PDO::FETCH_KEY_PAIR);
        $expected = [
            'otp_ttl_minutes' => '10',
            'otp_max_attempts' => '5',
            'external_forwarding' => 'allow',
            'superadmin_list_override' => 'allow',
            'retention_suspended_days' => '30',
            'retention_archive_days' => '90',
            'max_message_mb' => '25',
            'quota_warn_levels' => '80,90,95',
            'admin_require_2fa' => 'no',
            'login_alert_new_country' => 'yes',
            'digest_hour_utc' => '6',
            'login_events_retention_days' => '90',
            'delivery_events_retention_days' => '30',
            'dmarc_retention_days' => '180',
        ];
        ksort($expected);
        $this->assertSame($expected, $settings);

        $global = $this->pdo()->query('SELECT * FROM filter_global')->fetchAll();
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

    // ---- 0007: mailbox profile, kind and security columns -------------------------

    public function test_new_mailbox_columns_and_defaults(): void
    {
        $stmt = $this->pdo()->prepare(
            'SELECT column_type, is_nullable, column_default, character_set_name FROM information_schema.columns '
            . 'WHERE table_schema = DATABASE() AND table_name = ? AND column_name = ?'
        );
        $expected = [
            'mailboxes.display_name' => ['varchar(128)', 'YES', 'NULL', 'utf8mb4'],
            'mailboxes.job_title' => ['varchar(128)', 'YES', 'NULL', 'utf8mb4'],
            'mailboxes.department' => ['varchar(128)', 'YES', 'NULL', 'utf8mb4'],
            'mailboxes.phone' => ['varchar(32)', 'YES', 'NULL', 'ascii'],
            'mailboxes.directory_visible' => ['tinyint(1)', 'NO', '1', null],
            'mailboxes.kind' => ["enum('personal','shared')", 'NO', "'personal'", 'utf8mb4'],
            'mailboxes.require_app_passwords' => ['tinyint(1)', 'NO', '0', null],
            'mailboxes.quota_warned_level' => ['tinyint(3) unsigned', 'NO', '0', null],
            'mailboxes.must_change_password' => ['tinyint(1)', 'NO', '0', null],
            'mailboxes.password_hash' => ['varchar(255)', 'YES', 'NULL', 'ascii'],
            'domains.mta_sts_mode' => ["enum('none','testing','enforce')", 'NO', "'testing'", 'utf8mb4'],
        ];

        foreach ($expected as $column => $shape) {
            [$table, $name] = explode('.', $column);
            $stmt->execute([$table, $name]);
            $this->assertSame($shape, $stmt->fetch(PDO::FETCH_NUM), $column);
        }
    }

    public function test_shared_mailbox_has_no_credentials(): void
    {
        $domainId = $this->domain('example.com');
        $insert = 'INSERT INTO mailboxes (domain_id, local_part, password_hash, recovery_email, kind) VALUES (?, ?, ?, ?, ?)';
        $rule = 'chk_mailboxes_kind_credentials';

        $this->assertSqlError(self::CHECK_FAILED, $insert, [$domainId, 'support', self::HASH_ARGON, null, 'shared'], $rule);
        $this->assertSqlError(self::CHECK_FAILED, $insert, [$domainId, 'support', null, 'boss@gmail.com', 'shared'], $rule);
        $this->assertSqlError(self::CHECK_FAILED, $insert, [$domainId, 'alice', null, null, 'personal'], $rule);
        $this->assertSqlError(
            self::CHECK_FAILED,
            'INSERT INTO mailboxes (domain_id, local_part, kind, require_app_passwords) VALUES (?, ?, ?, 1)',
            [$domainId, 'support', 'shared'],
            $rule
        );

        $shared = $this->sharedMailbox($domainId, 'support');
        $this->assertSame(
            ['shared', null, null],
            $this->query('SELECT kind, password_hash, recovery_email FROM mailboxes WHERE id = ?', [$shared])->fetch(PDO::FETCH_NUM)
        );

        // A personal mailbox cannot lose its password later, and a shared one cannot gain one.
        $personal = $this->mailbox($domainId, 'alice');
        $this->assertSqlError(self::CHECK_FAILED, 'UPDATE mailboxes SET password_hash = NULL WHERE id = ?', [$personal], $rule);
        $this->assertSqlError(
            self::CHECK_FAILED,
            'UPDATE mailboxes SET password_hash = ? WHERE id = ?',
            [self::HASH_ARGON, $shared],
            $rule
        );
    }

    /**
     * @dataProvider badProfileValues
     */
    public function test_profile_text_rules(string $column, string $value, string $constraint): void
    {
        $mailbox = $this->mailbox($this->domain('example.com'), 'alice');

        $this->assertSqlError(self::CHECK_FAILED, "UPDATE mailboxes SET $column = ? WHERE id = ?", [$value, $mailbox], $constraint);
    }

    /** @return array<string,array{string,string,string}> */
    public function badProfileValues(): array
    {
        $cases = [];
        foreach (['display_name', 'job_title', 'department'] as $column) {
            foreach (['empty' => '', 'a newline' => "a\nb", 'a tab' => "a\tb"] as $what => $value) {
                $cases["$column with $what"] = [$column, $value, "chk_mailboxes_{$column}_text"];
            }
        }
        foreach (['letters' => 'abc', 'one digit' => '1', 'a trailing newline' => "+265 99 123 4567\n"] as $what => $value) {
            $cases["phone with $what"] = ['phone', $value, 'chk_mailboxes_phone_format'];
        }

        return $cases;
    }

    public function test_profile_text_accepts_valid_values(): void
    {
        $domainId = $this->domain('example.com');
        $update = 'UPDATE mailboxes SET display_name = ?, job_title = ?, department = ?, phone = ? WHERE id = ?';

        $this->query($update, ['Chikondi Banda', 'Head of Finance', 'Finance', '+265 991 234 567', $this->mailbox($domainId, 'a')]);
        $this->query($update, ['Zoë Ménard', 'Ingénieure', 'R&D', '(01) 234-5678', $this->mailbox($domainId, 'b')]);

        $this->assertSame(
            ['Chikondi Banda', 'Zoë Ménard'],
            $this->pdo()->query('SELECT display_name FROM mailboxes ORDER BY id')->fetchAll(PDO::FETCH_COLUMN)
        );
    }

    public function test_quota_warned_level_bounds(): void
    {
        $mailbox = $this->mailbox($this->domain('example.com'), 'alice');

        $this->assertSqlError(
            self::CHECK_FAILED,
            'UPDATE mailboxes SET quota_warned_level = 101 WHERE id = ?',
            [$mailbox],
            'chk_mailboxes_quota_warned_level_range'
        );
        $this->query('UPDATE mailboxes SET quota_warned_level = 95 WHERE id = ?', [$mailbox]);
        $this->assertSame(95, (int) $this->scalar('SELECT quota_warned_level FROM mailboxes WHERE id = ?', [$mailbox]));
    }

    public function test_existing_rows_get_defaults(): void
    {
        $domainId = $this->domain('example.com');
        $mailbox = $this->mailbox($domainId, 'alice');

        $this->assertEquals(
            ['personal', 1, 0, 0, 0, null],
            $this->query(
                'SELECT kind, directory_visible, require_app_passwords, must_change_password, quota_warned_level, display_name '
                . 'FROM mailboxes WHERE id = ?',
                [$mailbox]
            )->fetch(PDO::FETCH_NUM)
        );
        $this->assertSame('testing', $this->scalar('SELECT mta_sts_mode FROM domains WHERE id = ?', [$domainId]));
    }

    // ---- 0008 / 0009: app passwords, 2FA and activity logs ------------------------

    public function test_app_password_rules(): void
    {
        $mailbox = $this->mailbox($this->domain('example.com'), 'alice');
        $insert = 'INSERT INTO app_passwords (mailbox_id, name, password_hash) VALUES (?, ?, ?)';

        $this->assertSqlError(self::CHECK_FAILED, $insert, [$mailbox, '', self::HASH_ARGON], 'chk_app_passwords_name_text');
        $this->assertSqlError(self::CHECK_FAILED, $insert, [$mailbox, "a\nb", self::HASH_ARGON], 'chk_app_passwords_name_text');
        // Argon2id only: app passwords are new, so there are no bcrypt hashes to carry over.
        $this->assertSqlError(
            self::CHECK_FAILED,
            $insert,
            [$mailbox, 'Phone', self::HASH_BCRYPT],
            'chk_app_passwords_password_hash_prefix'
        );

        $id = $this->appPassword($mailbox, 'Thunderbird – laptop');
        $this->assertSame(
            [null, null],
            $this->query('SELECT last_used_at, revoked_at FROM app_passwords WHERE id = ?', [$id])->fetch(PDO::FETCH_NUM)
        );

        $this->query('DELETE FROM mailboxes WHERE id = ?', [$mailbox]);
        $this->assertSame(0, (int) $this->scalar('SELECT COUNT(*) FROM app_passwords'));
    }

    public function test_totp_one_secret_per_subject(): void
    {
        $insert = 'INSERT INTO totp_secrets (subject_type, subject_id, secret_enc) VALUES (?, ?, ?)';
        $this->query($insert, ['mailbox', 1, 'ciphertext-1']);
        $this->query($insert, ['admin', 1, 'ciphertext-2']);

        $this->assertSqlError(self::DUPLICATE_KEY, $insert, ['mailbox', 1, 'ciphertext-3']);
        $this->assertSame(2, (int) $this->scalar('SELECT COUNT(*) FROM totp_secrets'));
    }

    public function test_recovery_code_rules(): void
    {
        $insert = 'INSERT INTO recovery_codes (subject_type, subject_id, code_hash) VALUES (?, ?, ?)';
        $this->assertSqlError(
            self::CHECK_FAILED,
            $insert,
            ['mailbox', 1, str_repeat('A', 64)],
            'chk_recovery_codes_code_hash_lc'
        );

        $hash = hash('sha256', 'abcd-efgh');
        $this->query($insert, ['mailbox', 1, $hash]);
        $this->query($insert, ['mailbox', 2, $hash]);
        $this->query($insert, ['admin', 1, $hash]);
        $this->assertSqlError(self::DUPLICATE_KEY, $insert, ['mailbox', 1, $hash]);
    }

    public function test_login_event_rules(): void
    {
        $mailbox = $this->mailbox($this->domain('example.com'), 'alice');
        $app = $this->appPassword($mailbox, 'Phone');
        $insert = 'INSERT INTO login_events (subject_type, subject_id, login, service, result, ip, country, app_password_id) '
            . "VALUES ('mailbox', ?, 'alice@example.com', 'imap', 'ok', '203.0.113.5', ?, ?)";

        $this->assertSqlError(self::CHECK_FAILED, $insert, [$mailbox, 'mw', $app], 'chk_login_events_country_format');
        $this->assertSqlError(self::CHECK_FAILED, $insert, [$mailbox, 'M1', $app], 'chk_login_events_country_format');
        $this->query($insert, [$mailbox, 'MW', $app]);
        $this->query($insert, [$mailbox, null, null]);

        // Revoking by deleting the app password keeps the history, without the link.
        $this->query('DELETE FROM app_passwords WHERE id = ?', [$app]);
        $this->assertSame(
            ['MW', null],
            $this->pdo()->query("SELECT country, app_password_id FROM login_events WHERE country = 'MW'")->fetch(PDO::FETCH_NUM)
        );
        $this->assertSame(2, (int) $this->scalar('SELECT COUNT(*) FROM login_events WHERE app_password_id IS NULL'));
    }

    public function test_delivery_event_rules(): void
    {
        $domainId = $this->domain('example.com');
        $insert = 'INSERT INTO delivery_events (queue_id, at, sender, recipient, status, recipient_domain_id) '
            . "VALUES ('4XyZ1', UTC_TIMESTAMP(3), ?, ?, 'sent', ?)";

        $this->assertSqlError(
            self::CHECK_FAILED,
            $insert,
            ['bob@gmail.com', 'Alice@example.com', $domainId],
            'chk_delivery_events_recipient_lc'
        );
        $this->assertSqlError(
            self::CHECK_FAILED,
            $insert,
            ['Bob@Gmail.com', 'alice@example.com', $domainId],
            'chk_delivery_events_sender_lc'
        );
        // A bounce has an empty envelope sender.
        $this->query($insert, ['', 'alice@example.com', $domainId]);
        $this->query($insert, ['bob@gmail.com', 'alice@example.com', $domainId]);

        // No foreign key: the delivery history outlives the domain.
        $this->query('DELETE FROM domains WHERE id = ?', [$domainId]);
        $this->assertSame(2, (int) $this->scalar('SELECT COUNT(*) FROM delivery_events WHERE recipient_domain_id = ?', [$domainId]));
    }

    // ---- 0010 to 0012: rules, out-of-office, spam lists, shared access, requests, jobs --

    private const SIEVE_INSERT = 'INSERT INTO sieve_rules '
        . '(mailbox_id, position, match_field, header_name, match_type, match_value, action, folder) '
        . 'VALUES (?, ?, ?, ?, ?, ?, ?, ?)';

    /**
     * Parameters for SIEVE_INSERT: a valid "subject contains invoice → flag" rule with $row on top.
     *
     * @param array<string,mixed> $row
     *
     * @return list<mixed>
     */
    private function sieveRow(int $mailboxId, array $row): array
    {
        $row += [
            'position' => 1,
            'match_field' => 'subject',
            'header_name' => null,
            'match_type' => 'contains',
            'match_value' => 'invoice',
            'action' => 'flag',
            'folder' => null,
        ];

        return [
            $mailboxId, $row['position'], $row['match_field'], $row['header_name'], $row['match_type'],
            $row['match_value'], $row['action'], $row['folder'],
        ];
    }

    /**
     * @dataProvider badSieveRules
     *
     * @param array<string,mixed> $row
     */
    public function test_sieve_rule_text_rules(array $row, string $constraint): void
    {
        $mailbox = $this->mailbox($this->domain('example.com'), 'alice');

        $this->assertSqlError(self::CHECK_FAILED, self::SIEVE_INSERT, $this->sieveRow($mailbox, $row), $constraint);
    }

    /**
     * Rule values and folder names are written into a Sieve script as quoted strings, so a quote,
     * a backslash or a control character must never reach them.
     *
     * @return array<string,array{array<string,mixed>,string}>
     */
    public function badSieveRules(): array
    {
        $value = 'chk_sieve_rules_match_value_text';
        $folder = 'chk_sieve_rules_folder_text';

        return [
            'value with a quote' => [['match_value' => 'a"b'], $value],
            'value with a backslash' => [['match_value' => 'a\\b'], $value],
            'value with a newline' => [['match_value' => "a\nb"], $value],
            'value empty' => [['match_value' => ''], $value],
            'folder starting with a slash' => [['action' => 'move', 'folder' => '/x'], $folder],
            'folder with a quote' => [['action' => 'move', 'folder' => 'a"b'], $folder],
            'folder with a backslash' => [['action' => 'move', 'folder' => 'a\\b'], $folder],
            'folder with a newline' => [['action' => 'move', 'folder' => "a\nb"], $folder],
            'folder empty' => [['action' => 'move', 'folder' => ''], $folder],
            'move without a folder' => [['action' => 'move'], 'chk_sieve_rules_folder_by_action'],
            'flag with a folder' => [['action' => 'flag', 'folder' => 'Work'], 'chk_sieve_rules_folder_by_action'],
            'header rule without a header name' => [['match_field' => 'header'], 'chk_sieve_rules_header_name_by_field'],
            'header name on a subject rule' => [['header_name' => 'X-Spam'], 'chk_sieve_rules_header_name_by_field'],
            'header name with a space' => [['match_field' => 'header', 'header_name' => 'X Spam'], 'chk_sieve_rules_header_name_format'],
            'header name with a colon' => [['match_field' => 'header', 'header_name' => 'X-Spam:'], 'chk_sieve_rules_header_name_format'],
        ];
    }

    public function test_sieve_rule_accepts_valid_rows(): void
    {
        $mailbox = $this->mailbox($this->domain('example.com'), 'alice');
        $rows = [
            ['position' => 1, 'match_field' => 'header', 'header_name' => 'X-Spam-Flag', 'match_type' => 'is', 'match_value' => 'YES', 'action' => 'trash'],
            ['position' => 2, 'match_field' => 'from', 'match_value' => 'boss@example.com', 'action' => 'move', 'folder' => 'Work/Boss'],
            ['position' => 3, 'match_field' => 'to_cc', 'match_value' => 'team@', 'action' => 'mark_read'],
            ['position' => 4, 'match_value' => 'Rechnung für März', 'action' => 'move', 'folder' => 'Rechnungen ü'],
            ['position' => 5, 'match_value' => 'newsletter', 'action' => 'stop'],
        ];
        foreach ($rows as $row) {
            $this->query(self::SIEVE_INSERT, $this->sieveRow($mailbox, $row));
        }

        $this->assertSame(5, (int) $this->scalar('SELECT COUNT(*) FROM sieve_rules WHERE active = 1'));
        $this->assertSqlError(self::DUPLICATE_KEY, self::SIEVE_INSERT, $this->sieveRow($mailbox, ['position' => 3]));

        $this->query('DELETE FROM mailboxes WHERE id = ?', [$mailbox]);
        $this->assertSame(0, (int) $this->scalar('SELECT COUNT(*) FROM sieve_rules'));
    }

    public function test_vacation_rules(): void
    {
        $domainId = $this->domain('example.com');
        $mailbox = $this->mailbox($domainId, 'alice');
        $insert = 'INSERT INTO vacation_settings (mailbox_id, starts_at, ends_at, subject, body, interval_days, time_zone) '
            . 'VALUES (?, ?, ?, ?, ?, ?, ?)';
        $ok = [$mailbox, '2026-12-20 00:00:00', '2027-01-05 00:00:00', 'Out of office', "Back on 5 January.\nRegards", 7, 'Africa/Blantyre'];
        $bad = function (int $index, mixed $value, string $constraint) use ($insert, $ok): void {
            $this->assertSqlError(self::CHECK_FAILED, $insert, array_replace($ok, [$index => $value]), $constraint);
        };

        $bad(2, '2026-12-19 00:00:00', 'chk_vacation_settings_dates_ordered');
        $bad(2, '2026-12-20 00:00:00', 'chk_vacation_settings_dates_ordered');
        $bad(3, '', 'chk_vacation_settings_subject_text');
        $bad(3, "a\nb", 'chk_vacation_settings_subject_text');
        $bad(4, '', 'chk_vacation_settings_body_length');
        $bad(4, str_repeat('a', 4097), 'chk_vacation_settings_body_length');
        $bad(5, 0, 'chk_vacation_settings_interval_range');
        $bad(5, 31, 'chk_vacation_settings_interval_range');
        $bad(6, 'x;y', 'chk_vacation_settings_time_zone_format');
        $bad(6, "UTC\n", 'chk_vacation_settings_time_zone_format');

        $this->query($insert, $ok);
        // 4096 characters is the limit, however many bytes they take.
        $other = $this->mailbox($domainId, 'bob');
        $this->query(
            'INSERT INTO vacation_settings (mailbox_id, subject, body) VALUES (?, ?, ?)',
            [$other, 'Away', str_repeat('é', 4096)]
        );
        $this->assertEquals(
            [0, 7, 'UTC', null, null],
            $this->query(
                'SELECT enabled, interval_days, time_zone, starts_at, ends_at FROM vacation_settings WHERE mailbox_id = ?',
                [$other]
            )->fetch(PDO::FETCH_NUM)
        );
    }

    public function test_spam_pattern_rules(): void
    {
        $mailbox = $this->mailbox($this->domain('example.com'), 'alice');
        $insert = 'INSERT INTO spam_sender_lists (mailbox_id, list_type, pattern) VALUES (?, ?, ?)';

        $this->assertSqlError(self::CHECK_FAILED, $insert, [$mailbox, 'block', 'Bob@x.com'], 'chk_spam_sender_lists_pattern_lc');
        foreach (['x.com', '@x', 'a,b@x.com', '@', 'bob@', "bob@x.com\n", 'a@b@x.com'] as $pattern) {
            $this->assertSqlError(self::CHECK_FAILED, $insert, [$mailbox, 'block', $pattern], 'chk_spam_sender_lists_pattern_format');
        }

        $this->query($insert, [$mailbox, 'allow', 'bob@x.com']);
        $this->query($insert, [$mailbox, 'block', '@x.com']);
        // One entry per pattern: the same sender cannot be allowed and blocked at once.
        $this->assertSqlError(self::DUPLICATE_KEY, $insert, [$mailbox, 'block', 'bob@x.com']);
    }

    public function test_shared_access_self(): void
    {
        $domainId = $this->domain('example.com');
        $shared = $this->sharedMailbox($domainId, 'support');
        $alice = $this->mailbox($domainId, 'alice');
        $insert = 'INSERT INTO shared_access (shared_mailbox_id, member_mailbox_id) VALUES (?, ?)';

        $this->assertSqlError(self::CHECK_FAILED, $insert, [$shared, $shared], 'chk_shared_access_not_self');

        $this->sharedAccess($shared, $alice);
        $this->assertSqlError(self::DUPLICATE_KEY, $insert, [$shared, $alice]);
        $this->assertSame(
            [1, 0],
            array_map('intval', $this->query('SELECT can_read, can_send FROM shared_access')->fetch(PDO::FETCH_NUM))
        );

        $this->query('DELETE FROM mailboxes WHERE id = ?', [$alice]);
        $this->assertSame(0, (int) $this->scalar('SELECT COUNT(*) FROM shared_access'));
    }

    public function test_migration_job_rules(): void
    {
        $mailbox = $this->mailbox($this->domain('example.com'), 'alice');
        $insert = 'INSERT INTO migration_jobs (mailbox_id, host, port, tls, username, password_enc, status, expires_at) '
            . 'VALUES (?, ?, ?, ?, ?, ?, ?, UTC_TIMESTAMP() + INTERVAL 7 DAY)';
        $ok = [$mailbox, 'imap.old-provider.com', 993, 'ssl', 'alice@old-provider.com', 'ciphertext', 'queued'];
        $bad = function (int $index, mixed $value, string $constraint) use ($insert, $ok): void {
            $this->assertSqlError(self::CHECK_FAILED, $insert, array_replace($ok, [$index => $value]), $constraint);
        };

        $bad(2, 0, 'chk_migration_jobs_port_range');
        $bad(1, 'Mail.Old.com', 'chk_migration_jobs_host_lc');
        $bad(1, 'mail_old.com', 'chk_migration_jobs_host_format');
        $bad(1, 'localhost', 'chk_migration_jobs_host_format');
        $bad(1, 'imap.old.com:993', 'chk_migration_jobs_host_format');
        $bad(4, '', 'chk_migration_jobs_username_text');
        foreach (['done', 'failed', 'cancelled'] as $finished) {
            $bad(6, $finished, 'chk_migration_jobs_password_cleared');
        }

        $job = $this->insertId($insert, $ok);
        $this->query($insert, [$mailbox, '192.0.2.10', 143, 'starttls', 'alice', null, 'done']);
        $this->assertSqlError(
            self::CHECK_FAILED,
            "UPDATE migration_jobs SET status = 'done' WHERE id = ?",
            [$job],
            'chk_migration_jobs_password_cleared'
        );
        $this->query("UPDATE migration_jobs SET status = 'done', password_enc = NULL WHERE id = ?", [$job]);
        $this->assertSame(2, (int) $this->scalar("SELECT COUNT(*) FROM migration_jobs WHERE status = 'done'"));
    }

    public function test_job_types_and_settings(): void
    {
        $insert = "INSERT INTO deployments (job_type, payload, requested_by_type) VALUES (?, '{}', 'system')";
        $new = ['domain_certs', 'sieve_compile', 'spam_lists', 'imap_migrate', 'domain_check'];
        foreach ($new as $type) {
            $this->query($insert, [$type]);
        }
        $this->assertSame($new, $this->pdo()->query('SELECT job_type FROM deployments ORDER BY id')->fetchAll(PDO::FETCH_COLUMN));

        $settings = $this->pdo()->query(
            "SELECT `key`, value FROM settings WHERE `key` IN ('quota_warn_levels', 'admin_require_2fa', "
            . "'login_alert_new_country', 'digest_hour_utc', 'login_events_retention_days', "
            . "'delivery_events_retention_days', 'dmarc_retention_days') ORDER BY `key`"
        )->fetchAll(PDO::FETCH_KEY_PAIR);
        $this->assertSame([
            'admin_require_2fa' => 'no',
            'delivery_events_retention_days' => '30',
            'digest_hour_utc' => '6',
            'dmarc_retention_days' => '180',
            'login_alert_new_country' => 'yes',
            'login_events_retention_days' => '90',
            'quota_warn_levels' => '80,90,95',
        ], $settings);
    }

    public function test_migrations_rerunnable(): void
    {
        $this->pdo()->exec('DELETE FROM schema_migrations');

        $this->migrateAll();

        $this->assertSame(20, (int) $this->scalar('SELECT COUNT(*) FROM role_permissions'));
        $this->assertSame(2, (int) $this->scalar('SELECT COUNT(*) FROM roles'));
        $this->assertSame(14, (int) $this->scalar('SELECT COUNT(*) FROM settings'));
        $this->assertSame(1, (int) $this->scalar('SELECT COUNT(*) FROM filter_global'));
        $this->assertSame(
            $this->migrationVersionsOnDisk(),
            $this->pdo()->query('SELECT version FROM schema_migrations ORDER BY version')->fetchAll(PDO::FETCH_COLUMN)
        );
    }

    /**
     * Versions of app/migrations/NNNN_name.sql, the pattern the Migrator accepts, so
     * adding a migration does not need an edit here.
     *
     * @return list<string>
     */
    private function migrationVersionsOnDisk(): array
    {
        $versions = [];
        foreach (glob(dirname(__DIR__, 2) . '/migrations/*.sql') ?: [] as $file) {
            if (preg_match('/^(\\d{4}_[a-z0-9_]+)\\.sql$/', basename($file), $match) === 1) {
                $versions[] = $match[1];
            }
        }
        sort($versions, SORT_STRING);
        $this->assertNotSame([], $versions, 'no migration files found');

        return $versions;
    }
}
