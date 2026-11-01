<?php

declare(strict_types=1);

namespace Mailhost\Tests\Integration;

use InvalidArgumentException;
use Mailhost\Db\Connection;
use Mailhost\Db\Grants;
use Mailhost\Db\UserProvisioner;
use PDO;
use PDOException;
use PDOStatement;

/**
 * What each of the five service accounts may and may not do on a migrated database.
 *
 * Every test provisions the accounts with fresh random passwords and then connects as
 * them over TCP, so the grants are exercised exactly as the services will use them.
 * A refused statement fails with MariaDB error 1142 (table access denied) or 1143
 * (column access denied), or 1369 when a view's CHECK OPTION refuses the row, asserted on
 * errorInfo[1], never on the message.
 */
final class GrantsMatrixTest extends DbTestCase
{
    use Fixtures;

    private const TABLE_DENIED = 1142;
    private const COLUMN_DENIED = 1143;
    private const ACCESS_DENIED = 1045;
    private const CHECK_OPTION_FAILED = 1369;

    private const HOSTS = ['localhost', '127.0.0.1'];
    private const CLI_DATABASE = 'mailhost_cli_test';

    /** An audit_log insert that names only the eight columns a service may write. */
    private const AUDIT_INSERT = 'INSERT INTO audit_log (actor_type, actor_id, action, target_type, target_id, domain_id, ip, details) '
        . "VALUES ('system', NULL, 'grants.test', NULL, NULL, NULL, NULL, NULL)";

    private const KICK = 'INSERT INTO v_portal_deployments (job_type, payload, requested_by_type, requested_by_id) '
        . "VALUES ('doveadm_kick', '{}', 'mailbox', 1)";

    /** @var array<string,string> */
    private array $passwords = [];

    protected function setUp(): void
    {
        parent::setUp();

        $this->freshDatabase();
        $this->migrateAll();

        $example = $this->domain('example.com');
        $this->mailbox($example, 'alice');
        $this->domain('gone.test');

        foreach (Grants::USERS as $user) {
            $this->passwords[$user] = bin2hex(random_bytes(16));
        }
        $this->provisioner()->provisionAll($this->passwords);
    }

    private function provisioner(): UserProvisioner
    {
        return new UserProvisioner($this->pdo(), self::DATABASE, self::HOSTS);
    }

    private function connectAs(string $user, ?string $password = null): PDO
    {
        return Connection::asUser($this->env(), $user, $password ?? $this->passwords[$user]);
    }

    /** @param list<int> $codes */
    private function assertDenied(PDO $pdo, string $sql, array $codes): void
    {
        try {
            $pdo->query($sql);
        } catch (PDOException $e) {
            $this->assertContains($e->errorInfo[1] ?? null, $codes, $e->getMessage() . ' for: ' . $sql);

            return;
        }

        $this->fail('Statement was not refused: ' . $sql);
    }

    /**
     * Like assertDenied(), for a prepared statement with parameters.
     *
     * @param list<mixed> $params
     */
    private function assertDeniedWith(PDO $pdo, int $code, string $sql, array $params): void
    {
        try {
            $pdo->prepare($sql)->execute($params);
        } catch (PDOException $e) {
            $this->assertSame($code, $e->errorInfo[1] ?? null, $e->getMessage() . ' for: ' . $sql);

            return;
        }

        $this->fail('Statement was not refused: ' . $sql);
    }

    public function test_tables_constant_matches_schema(): void
    {
        $tables = $this->col(
            "SELECT table_name FROM information_schema.tables WHERE table_schema = ? AND table_type = 'BASE TABLE' "
            . "AND table_name <> 'schema_migrations'",
            [self::DATABASE]
        );

        $expected = Grants::TABLES;
        sort($expected, SORT_STRING);

        $this->assertSame($expected, $tables);
    }

    /**
     * @dataProvider matrix
     */
    public function test_matrix(string $user, string $sql, bool $allowed): void
    {
        $pdo = $this->connectAs($user);

        if ($allowed) {
            $this->assertInstanceOf(PDOStatement::class, $pdo->query($sql));

            return;
        }

        $this->assertDenied($pdo, $sql, [self::TABLE_DENIED, self::COLUMN_DENIED]);
    }

    /** @return array<string,array{string,string,bool}> */
    public function matrix(): array
    {
        $rows = [];
        $add = static function (string $user, string $sql, bool $allowed) use (&$rows): void {
            $rows[sprintf('%s %s: %s', $user, $allowed ? 'may' : 'may not', $sql)] = [$user, $sql, $allowed];
        };

        foreach (['v_domains', 'v_mailboxes', 'v_auth', 'v_aliases', 'v_sender_login', 'v_rejected_recipients'] as $view) {
            $add('mail_ro', "SELECT * FROM $view", true);
        }
        $add('mail_ro', 'SELECT * FROM mailboxes', false);
        $add('mail_ro', 'SELECT * FROM v_lists', false);
        $add('mail_ro', 'SELECT * FROM v_local_addresses', false);
        $add('mail_ro', 'SELECT * FROM v_list_addresses', false);
        $add('mail_ro', 'SELECT * FROM v_rejected_local', false);
        $add('mail_ro', 'SELECT * FROM schema_migrations', false);
        $add('mail_ro', self::AUDIT_INSERT, false);

        foreach (['v_domains', 'v_lists', 'v_list_sender_rules', 'v_login_roles', 'settings'] as $object) {
            $add('mail_policy', "SELECT * FROM $object", true);
        }
        $add('mail_policy', self::AUDIT_INSERT, true);
        $add('mail_policy', 'SELECT * FROM v_auth', false);
        $add('mail_policy', 'SELECT * FROM mailboxes', false);
        $add('mail_policy', 'SELECT * FROM audit_log', false);
        $add('mail_policy', "UPDATE settings SET value = '1'", false);
        $add('mail_policy', 'SELECT * FROM v_local_addresses', false);
        $add('mail_policy', 'SELECT * FROM v_list_addresses', false);

        $add('mail_app', 'UPDATE mailboxes SET quota_mb=quota_mb', true);
        $add('mail_app', 'SELECT * FROM audit_log', true);
        $add('mail_app', self::AUDIT_INSERT, true);
        $add('mail_app', "UPDATE audit_log SET action='x'", false);
        $add('mail_app', 'DELETE FROM audit_log', false);
        $add('mail_app', 'SELECT * FROM schema_migrations', false);
        $add('mail_app', 'SELECT * FROM v_auth', false);
        $add('mail_app', 'SELECT * FROM v_local_addresses', false);

        $add('mail_portal', 'SELECT * FROM mailboxes', true);
        $add('mail_portal', 'UPDATE mailboxes SET password_hash=password_hash', true);
        $add('mail_portal', 'SELECT * FROM v_portal_sessions', true);
        $add('mail_portal', 'DELETE FROM v_portal_sessions', true);
        $add('mail_portal', 'SELECT * FROM v_portal_otp_codes', true);
        $add('mail_portal', 'DELETE FROM v_portal_otp_codes', true);
        $add('mail_portal', self::KICK, true);
        $add('mail_portal', self::AUDIT_INSERT, true);
        $add('mail_portal', 'UPDATE mailboxes SET quota_mb=1', false);
        $add('mail_portal', 'DELETE FROM mailboxes', false);
        $add('mail_portal', 'SELECT * FROM admins', false);
        $add('mail_portal', 'SELECT * FROM audit_log', false);
        $add('mail_portal', "UPDATE audit_log SET action='x'", false);
        $add(
            'mail_portal',
            "INSERT INTO deployments (job_type, payload, requested_by_type) VALUES ('doveadm_kick', '{}', 'mailbox')",
            false
        );
        $add('mail_portal', 'SELECT * FROM v_local_addresses', false);
        $add('mail_portal', 'SELECT * FROM sessions', false);
        $add('mail_portal', 'DELETE FROM sessions', false);
        $add('mail_portal', 'SELECT * FROM otp_codes', false);
        $add('mail_portal', 'DELETE FROM otp_codes', false);

        $add('mailctl', 'UPDATE deployments SET status=status', true);
        $add('mailctl', 'UPDATE mailboxes SET quota_used_bytes=0', true);
        $add('mailctl', "DELETE FROM domains WHERE name='gone.test'", true);
        $add('mailctl', 'SELECT * FROM v_auth', true);
        $add('mailctl', self::AUDIT_INSERT, true);
        $add('mailctl', 'UPDATE mailboxes SET password_hash=password_hash', false);
        $add(
            'mailctl',
            "INSERT INTO admins (username, email, password_hash, role_id, status) VALUES ('x', 'x@admins.example', 'x', 1, 'active')",
            false
        );
        $add('mailctl', "UPDATE audit_log SET action='x'", false);
        $add('mailctl', 'DELETE FROM audit_log', false);

        return $rows;
    }

    public function test_column_level_inserts(): void
    {
        $portal = $this->connectAs('mail_portal');

        // The portal may name only the four job columns of v_portal_deployments, and may not read it.
        $this->assertDenied(
            $portal,
            'INSERT INTO v_portal_deployments (id, job_type, payload, requested_by_type, requested_by_id) '
            . "VALUES (999, 'doveadm_kick', '{}', 'mailbox', 1)",
            [self::COLUMN_DENIED]
        );
        $this->assertDenied($portal, 'SELECT * FROM v_portal_deployments', [self::TABLE_DENIED]);
        $this->assertDenied($portal, "UPDATE v_portal_deployments SET payload = '{}'", [self::TABLE_DENIED]);
        $this->assertDenied($portal, 'DELETE FROM v_portal_deployments', [self::TABLE_DENIED]);

        // Every writer of audit_log may set the eight caller columns, never the id or the timestamp.
        foreach (['mail_policy', 'mail_app', 'mail_portal', 'mailctl'] as $user) {
            $pdo = $this->connectAs($user);

            $this->assertSame(
                1,
                $pdo->exec(self::AUDIT_INSERT),
                "$user must be able to insert the eight allowed audit_log columns"
            );
            $this->assertDenied(
                $pdo,
                "INSERT INTO audit_log (id, actor_type, action) VALUES (900000, 'system', 'x')",
                [self::COLUMN_DENIED]
            );
            $this->assertDenied(
                $pdo,
                "INSERT INTO audit_log (at, actor_type, action) VALUES ('2000-01-01 00:00:00', 'system', 'x')",
                [self::COLUMN_DENIED]
            );
        }

        $this->assertSame(4, (int) $this->pdo()->query("SELECT COUNT(*) FROM audit_log WHERE action = 'grants.test'")->fetchColumn());
    }

    /**
     * The portal reaches sessions only through v_portal_sessions, which holds mailbox sessions
     * only: it can run the whole mailbox session life cycle, but cannot touch the table, see
     * or create an admin session, or rewrite who a session belongs to.
     */
    public function test_portal_sessions_only_through_the_mailbox_view(): void
    {
        $admin = hash('sha256', 'admin-token');
        $this->pdo()->prepare(
            'INSERT INTO sessions (token_hash, subject_type, subject_id, expires_at, ip, user_agent) '
            . "VALUES (?, 'admin', 1, '2030-01-01 00:00:00', '127.0.0.1', 'admin app')"
        )->execute([$admin]);

        $portal = $this->connectAs('mail_portal');
        $mine = hash('sha256', 'mailbox-token');
        $other = hash('sha256', 'other-token');

        foreach ([
            'SELECT * FROM sessions',
            "UPDATE sessions SET revoked_at = '2029-01-01 00:00:00'",
            'DELETE FROM sessions',
            'INSERT INTO sessions (token_hash, subject_type, subject_id, expires_at, ip, user_agent) '
                . "VALUES ('$other', 'mailbox', 1, '2030-01-01 00:00:00', '203.0.113.5', 'x')",
        ] as $sql) {
            $this->assertDenied($portal, $sql, [self::TABLE_DENIED]);
        }

        $insert = 'INSERT INTO v_portal_sessions (token_hash, subject_type, subject_id, expires_at, ip, user_agent) '
            . "VALUES (?, ?, 1, '2030-01-01 00:00:00', '203.0.113.5', 'browser')";
        $this->assertDeniedWith($portal, self::CHECK_OPTION_FAILED, $insert, [$other, 'admin']);

        // The mailbox life cycle: create, read, touch and extend, revoke, delete.
        $portal->prepare($insert)->execute([$mine, 'mailbox']);
        $this->assertSame([$mine], $portal->query('SELECT token_hash FROM v_portal_sessions')->fetchAll(PDO::FETCH_COLUMN));
        $this->assertSame(1, $portal->exec(
            "UPDATE v_portal_sessions SET last_seen_at = '2029-06-01 00:00:00', expires_at = '2031-01-01 00:00:00', "
            . "revoked_at = '2029-06-02 00:00:00' WHERE token_hash = '$mine'"
        ));

        foreach ([
            'token_hash' => "'$other'",
            'subject_type' => "'admin'",
            'subject_id' => '2',
            'created_at' => "'2000-01-01 00:00:00'",
            'ip' => "'198.51.100.1'",
            'user_agent' => "'x'",
        ] as $column => $value) {
            $this->assertDenied($portal, "UPDATE v_portal_sessions SET $column = $value WHERE token_hash = '$mine'", [self::COLUMN_DENIED]);
        }

        $this->assertSame(1, $portal->exec('DELETE FROM v_portal_sessions'));

        $this->assertSame(
            ["$admin admin not-revoked"],
            $this->col("SELECT CONCAT(token_hash, ' ', subject_type, ' ', IF(revoked_at IS NULL, 'not-revoked', 'revoked')) FROM sessions")
        );
    }

    /**
     * The portal reaches one-time codes only through v_portal_otp_codes, which holds mailbox
     * codes only. It may count attempts and mark a code used, never re-target, re-key or
     * extend one, and it never chooses the row id.
     */
    public function test_portal_codes_only_through_the_mailbox_view(): void
    {
        $this->pdo()->exec(
            'INSERT INTO otp_codes (subject_type, subject_id, purpose, code_hmac, expires_at, request_ip) '
            . "VALUES ('admin', 1, 'login', REPEAT('b', 64), '2030-01-01 00:00:00', '127.0.0.1')"
        );

        $portal = $this->connectAs('mail_portal');

        foreach ([
            'SELECT * FROM otp_codes',
            'UPDATE otp_codes SET attempts = 0',
            'DELETE FROM otp_codes',
            'INSERT INTO otp_codes (subject_type, subject_id, purpose, code_hmac, expires_at, request_ip) '
                . "VALUES ('mailbox', 1, 'login', REPEAT('c', 64), '2030-01-01 00:00:00', '203.0.113.5')",
        ] as $sql) {
            $this->assertDenied($portal, $sql, [self::TABLE_DENIED]);
        }

        $insert = 'INSERT INTO v_portal_otp_codes (subject_type, subject_id, purpose, code_hmac, target, expires_at, request_ip) '
            . "VALUES (?, 1, 'verify_email', REPEAT('a', 64), 'new@example.org', '2030-01-01 00:00:00', '203.0.113.5')";
        $this->assertDeniedWith($portal, self::CHECK_OPTION_FAILED, $insert, ['admin']);
        $this->assertDenied(
            $portal,
            'INSERT INTO v_portal_otp_codes (id, subject_type, subject_id, purpose, code_hmac, expires_at, request_ip) '
            . "VALUES (18446744073709551615, 'mailbox', 1, 'login', REPEAT('a', 64), '2030-01-01 00:00:00', '203.0.113.5')",
            [self::COLUMN_DENIED]
        );

        // The mailbox life cycle: create, read, count an attempt, mark used, delete.
        $portal->prepare($insert)->execute(['mailbox']);
        $id = (int) $portal->lastInsertId();
        $this->assertGreaterThan(0, $id);
        $this->assertSame(
            ["$id mailbox new@example.org"],
            $portal->query("SELECT CONCAT(id, ' ', subject_type, ' ', target) FROM v_portal_otp_codes")->fetchAll(PDO::FETCH_COLUMN)
        );
        $this->assertSame(1, $portal->exec("UPDATE v_portal_otp_codes SET attempts = attempts + 1, used_at = '2029-06-01 00:00:00' WHERE id = $id"));

        foreach ([
            'subject_type' => "'admin'",
            'subject_id' => '2',
            'code_hmac' => "REPEAT('d', 64)",
            'purpose' => "'recovery'",
            'target' => "'attacker@example.org'",
            'expires_at' => "'2031-01-01 00:00:00'",
            'id' => '1',
        ] as $column => $value) {
            $this->assertDenied($portal, "UPDATE v_portal_otp_codes SET $column = $value WHERE id = $id", [self::COLUMN_DENIED]);
        }

        $this->assertSame(1, $portal->exec('DELETE FROM v_portal_otp_codes'));

        $this->assertSame(
            ['admin 0'],
            $this->col("SELECT CONCAT(subject_type, ' ', attempts) FROM otp_codes")
        );
    }

    public function test_mailctl_database_grant_does_not_reach_sibling_databases(): void
    {
        // In a database-level grant "_" matches any one character, so an unescaped
        // `mailhost_test`.* would also cover a sibling database such as mailhostXtest.
        $sibling = 'mailhostXtest';
        $this->pdo()->exec("DROP DATABASE IF EXISTS `$sibling`");
        $this->pdo()->exec("CREATE DATABASE `$sibling`");

        try {
            $this->pdo()->exec("CREATE TABLE `$sibling`.secrets (x INT)");
            $this->pdo()->exec("INSERT INTO `$sibling`.secrets VALUES (1)");

            $mailctl = $this->connectAs('mailctl');

            // Control: the database it was provisioned for stays readable.
            $this->assertInstanceOf(PDOStatement::class, $mailctl->query('SELECT * FROM v_auth'));
            $this->assertDenied($mailctl, "SELECT * FROM `$sibling`.secrets", [self::TABLE_DENIED]);
        } finally {
            $this->pdo()->exec("DROP DATABASE IF EXISTS `$sibling`");
        }
    }

    public function test_reprovision_rotates_password(): void
    {
        $first = bin2hex(random_bytes(16));
        $second = bin2hex(random_bytes(16));

        $this->provisioner()->provision('mail_ro', $first);
        $grantLines = $this->grantLines('mail_ro', '127.0.0.1');
        $this->assertNotEmpty($grantLines);

        $this->provisioner()->provision('mail_ro', $second);

        try {
            $this->connectAs('mail_ro', $first);
            $this->fail('The old password still works');
        } catch (PDOException $e) {
            $this->assertSame(self::ACCESS_DENIED, $e->errorInfo[1] ?? null, $e->getMessage());
        }

        $this->assertInstanceOf(PDOStatement::class, $this->connectAs('mail_ro', $second)->query('SELECT * FROM v_auth'));
        $this->assertSame(count($grantLines), count($this->grantLines('mail_ro', '127.0.0.1')));
    }

    public function test_reprovision_removes_stray_grants(): void
    {
        $this->pdo()->exec('GRANT SELECT ON ' . self::DATABASE . ".mailboxes TO mail_ro@'127.0.0.1'");
        $this->assertInstanceOf(PDOStatement::class, $this->connectAs('mail_ro')->query('SELECT * FROM mailboxes'));

        $password = bin2hex(random_bytes(16));
        $this->provisioner()->provision('mail_ro', $password);

        $this->assertDenied(
            $this->connectAs('mail_ro', $password),
            'SELECT * FROM mailboxes',
            [self::TABLE_DENIED]
        );
    }

    public function test_provisions_every_host(): void
    {
        $accounts = $this->col(
            "SELECT CONCAT(user, '@', host) FROM mysql.user WHERE user IN ('mail_ro', 'mail_policy', 'mail_app', 'mail_portal', 'mailctl')"
        );

        $expected = [];
        foreach (Grants::USERS as $user) {
            foreach (self::HOSTS as $host) {
                $expected[] = "$user@$host";
            }
        }
        sort($expected, SORT_STRING);

        $this->assertSame($expected, $accounts);
    }

    /**
     * @dataProvider badInput
     */
    public function test_rejects_bad_input(string $user, string $password): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->provisioner()->provision($user, $password);
    }

    /** @return array<string,array{string,string}> */
    public function badInput(): array
    {
        $valid = str_repeat('a', 32);

        return [
            'user outside the list' => ['root', $valid],
            'user with a host' => ['mail_ro@localhost', $valid],
            'short password' => ['mail_ro', 'short'],
            'one character short' => ['mail_ro', str_repeat('a', 23)],
            'one character long' => ['mail_ro', str_repeat('a', 129)],
            'quote in password' => ['mail_ro', str_repeat('a', 31) . "'"],
            'space in password' => ['mail_ro', str_repeat('a', 31) . ' '],
            'trailing newline' => ['mail_ro', $valid . "\n"],
            'empty password' => ['mail_ro', ''],
        ];
    }

    public function test_longest_valid_password_works(): void
    {
        $password = str_repeat('aB3+/=._~-', 12) . 'abcdefgh';
        $this->assertSame(128, strlen($password));

        $this->provisioner()->provision('mail_ro', $password);

        $this->assertInstanceOf(PDOStatement::class, $this->connectAs('mail_ro', $password)->query('SELECT * FROM v_auth'));
    }

    public function test_provision_all_validates_everything_before_touching_the_server(): void
    {
        $unchanged = $this->passwords;
        $bad = $this->passwords;
        $bad['mailctl'] = 'short';

        try {
            $this->provisioner()->provisionAll($bad);
            $this->fail('A short password was accepted');
        } catch (InvalidArgumentException) {
            // expected
        }

        // mail_ro is first in the list: it must still have its original password.
        $this->assertInstanceOf(PDOStatement::class, $this->connectAs('mail_ro', $unchanged['mail_ro'])->query('SELECT * FROM v_auth'));
    }

    /**
     * @dataProvider badPasswordSets
     *
     * @param array<array-key,mixed> $passwords
     */
    public function test_provision_all_needs_exactly_the_five_users(array $passwords): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->provisioner()->provisionAll($passwords);
    }

    /** @return array<string,array{array<array-key,mixed>}> */
    public function badPasswordSets(): array
    {
        $valid = str_repeat('a', 32);
        $all = array_fill_keys(Grants::USERS, $valid);

        $missing = $all;
        unset($missing['mailctl']);

        return [
            'one user missing' => [$missing],
            'unknown user' => [$all + ['root' => $valid]],
            'non-string password' => [array_replace($all, ['mail_ro' => 12345])],
            'nothing' => [[]],
        ];
    }

    /**
     * @dataProvider badConstructorArguments
     *
     * @param list<string> $hosts
     */
    public function test_constructor_rejects_bad_database_and_hosts(string $db, array $hosts): void
    {
        $this->expectException(InvalidArgumentException::class);
        new UserProvisioner($this->pdo(), $db, $hosts);
    }

    /** @return array<string,array{string,list<string>}> */
    public function badConstructorArguments(): array
    {
        return [
            'database with backtick' => ['mail`host', ['localhost']],
            'database with trailing newline' => ["mailhost\n", ['localhost']],
            'empty database' => ['', ['localhost']],
            'no hosts' => ['mailhost', []],
            'empty host' => ['mailhost', ['']],
            'host with quote' => ['mailhost', ["x'@'%"]],
            'host with space' => ['mailhost', ['local host']],
            'host with trailing newline' => ['mailhost', ["localhost\n"]],
        ];
    }

    public function test_cli_db_users(): void
    {
        $env = array_replace($this->env(), ['DB_NAME' => self::CLI_DATABASE]);
        Connection::root($env, false)->exec('DROP DATABASE IF EXISTS `' . self::CLI_DATABASE . '`');

        $dir = sys_get_temp_dir() . '/mailhostctl-users-' . bin2hex(random_bytes(6));
        $this->assertTrue(mkdir($dir, 0700));
        $envFile = $dir . '/db.env';

        $passwords = [];
        foreach (Grants::USERS as $user) {
            $passwords['DB_PASS_' . strtoupper($user)] = bin2hex(random_bytes(16));
        }

        try {
            $this->writeEnvFile($envFile, $env + $passwords);

            [$code, , $err] = $this->ctl($envFile, 'migrate');
            $this->assertSame(0, $code, $err);

            [$code, $out, $err] = $this->ctl($envFile, 'db:users');
            $this->assertSame(0, $code, $err);
            $this->assertSame('', $err);

            $expected = '';
            foreach (Grants::USERS as $user) {
                foreach (['localhost', '127.0.0.1'] as $host) {
                    $expected .= "Provisioned $user@$host\n";
                }
            }
            $this->assertSame($expected, $out);
            $this->assertCount(10, explode("\n", rtrim($out, "\n")));

            // The passwords from the env file work, on the database named in the env file.
            $this->assertInstanceOf(
                PDOStatement::class,
                Connection::asUser($env, 'mail_ro', $passwords['DB_PASS_MAIL_RO'])->query('SELECT * FROM v_auth')
            );

            // A missing password is an error that names the env key, and nothing is changed.
            $rotated = array_replace($passwords, ['DB_PASS_MAIL_RO' => bin2hex(random_bytes(16))]);
            unset($rotated['DB_PASS_MAILCTL']);
            $this->writeEnvFile($envFile, $env + $rotated);

            [$code, $out, $err] = $this->ctl($envFile, 'db:users');
            $this->assertSame(1, $code);
            $this->assertSame('', $out);
            $this->assertMatchesRegularExpression('/DB_PASS_MAILCTL/', $err);
            $this->assertDoesNotMatchRegularExpression('/DB_PASS_MAIL_RO/', $err);
            $this->assertInstanceOf(
                PDOStatement::class,
                Connection::asUser($env, 'mail_ro', $passwords['DB_PASS_MAIL_RO'])->query('SELECT * FROM v_auth')
            );
        } finally {
            @unlink($envFile);
            @rmdir($dir);
            Connection::root($env, false)->exec('DROP DATABASE IF EXISTS `' . self::CLI_DATABASE . '`');
        }
    }

    /** @param array<string,string> $values */
    private function writeEnvFile(string $path, array $values): void
    {
        $lines = [];
        foreach ($values as $key => $value) {
            $lines[] = "$key=$value";
        }

        file_put_contents($path, implode("\n", $lines) . "\n");
        chmod($path, 0600);
    }

    /** @return list<string> */
    private function grantLines(string $user, string $host): array
    {
        return $this->pdo()
            ->query('SHOW GRANTS FOR ' . $this->pdo()->quote($user) . '@' . $this->pdo()->quote($host))
            ->fetchAll(PDO::FETCH_COLUMN);
    }

    /** @return array{0:int,1:string,2:string} exit code, stdout, stderr */
    private function ctl(string $envFile, string ...$args): array
    {
        $process = proc_open(
            [dirname(__DIR__, 2) . '/bin/mailhostctl', ...$args],
            [1 => ['pipe', 'w'], 2 => ['pipe', 'w']],
            $pipes,
            null,
            [
                'PATH' => getenv('PATH') ?: '/usr/local/bin:/usr/bin:/bin',
                'MAILHOST_DB_ENV' => $envFile,
            ]
        );
        $this->assertIsResource($process);

        $stdout = (string) stream_get_contents($pipes[1]);
        $stderr = (string) stream_get_contents($pipes[2]);
        fclose($pipes[1]);
        fclose($pipes[2]);

        return [proc_close($process), $stdout, $stderr];
    }
}
