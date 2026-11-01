<?php

declare(strict_types=1);

namespace Mailhost\Tests\Integration;

use Mailhost\Db\SqlSplitter;
use PDO;

/**
 * The views Postfix and Dovecot read (migration 0005).
 *
 * Every test starts from the same fixture (see buildFixture()) and asserts which
 * rows each view returns. Suspension must show up in the very next query, so the
 * tests change rows on the same connection and read the views straight away.
 */
final class MailViewsTest extends DbTestCase
{
    use Fixtures;

    /** The mail views of 0005 and the columns each one exposes, in order. */
    private const COLUMNS = [
        'v_domains' => ['name'],
        'v_local_addresses' => ['domain_id', 'local_part'],
        'v_mailboxes' => ['email', 'maildir', 'quota_mb'],
        'v_auth' => ['email', 'password'],
        'v_aliases' => ['source', 'destination'],
        'v_sender_login' => ['sender', 'login'],
        'v_rejected_local' => ['domain_id', 'local_part', 'reason'],
        'v_rejected_recipients' => ['email', 'reason'],
    ];

    private int $example;
    private int $other;
    private int $alice;
    private int $bob;
    private int $carol;
    private int $dave;
    private int $erin;
    private int $team;
    private int $old;

    protected function setUp(): void
    {
        parent::setUp();

        $this->freshDatabase();
        $this->migrateAll();
        $this->buildFixture();
    }

    /**
     * example.com is active and other.org is suspended, each with an alias domain.
     *
     * - alice: active, Argon2id, no forwarding.
     * - bob: suspended, forwards to bob@gmail.com and keeps a copy.
     * - carol: active, bcrypt, forwards to carol@gmail.com without a copy.
     * - dave: active, forwards to dave@gmail.com and keeps a copy.
     * - erin: active, but her domain other.org is suspended.
     *
     * Alias sales@ points at alice and dave. There are no catch-all aliases.
     * team@ is a universal list whose members are alice, bob (mailbox suspended),
     * dave (member row suspended) and erin (domain suspended). old@ is a suspended
     * list with alice as a member.
     */
    private function buildFixture(): void
    {
        $this->example = $this->domain('example.com');
        $this->other = $this->domain('other.org', 'suspended');
        $this->aliasDomain('example.net', $this->example);
        $this->aliasDomain('other.net', $this->other);

        $this->alice = $this->mailbox($this->example, 'alice');
        $this->bob = $this->mailbox($this->example, 'bob', 'suspended');
        $this->forward($this->bob, 'bob@gmail.com', true);
        $this->carol = $this->mailbox($this->example, 'carol', 'active', self::BCRYPT);
        $this->forward($this->carol, 'carol@gmail.com', false);
        $this->dave = $this->mailbox($this->example, 'dave');
        $this->forward($this->dave, 'dave@gmail.com', true);
        $this->erin = $this->mailbox($this->other, 'erin');

        $this->alias($this->example, 'sales', ['alice@example.com', 'dave@example.com']);

        $this->team = $this->mailList($this->example, 'team', 'universal');
        $this->member($this->team, $this->alice);
        $this->member($this->team, $this->bob);
        $this->member($this->team, $this->dave, 'suspended');
        $this->member($this->team, $this->erin);
        $this->old = $this->mailList($this->example, 'old', 'domain', 'suspended');
        $this->member($this->old, $this->alice);
    }

    // ---- helpers -----------------------------------------------------------------

    /** @return list<string> */
    private function destinations(string $source): array
    {
        return $this->col('SELECT destination FROM v_aliases WHERE source = ?', [$source]);
    }

    /** @return list<string> */
    private function logins(string $sender): array
    {
        return $this->col('SELECT login FROM v_sender_login WHERE sender = ?', [$sender]);
    }

    /**
     * The whole v_rejected_recipients view as sorted 'email reason' strings.
     *
     * @return list<string>
     */
    private function rejected(): array
    {
        return $this->col("SELECT CONCAT(email, ' ', reason) FROM v_rejected_recipients");
    }

    /** @param list<mixed> $params */
    private function exec(string $sql, array $params = []): void
    {
        $this->pdo()->prepare($sql)->execute($params);
    }

    // ---- shape -------------------------------------------------------------------

    public function test_views_expose_exactly_the_documented_columns(): void
    {
        foreach (self::COLUMNS as $view => $columns) {
            $actual = $this->pdo()->query(
                "SELECT column_name FROM information_schema.columns WHERE table_schema = DATABASE() "
                . "AND table_name = '$view' ORDER BY ordinal_position"
            )->fetchAll(PDO::FETCH_COLUMN);

            $this->assertSame($columns, $actual, $view);
        }
    }

    /**
     * Only the mail views of 0005. The policy and portal views of 0006 have enum and JSON
     * columns that keep the table collation; PolicyViewsTest checks their identifier columns.
     */
    public function test_every_text_column_is_ascii_bin(): void
    {
        $views = array_keys(self::COLUMNS);
        $stmt = $this->pdo()->prepare(
            "SELECT CONCAT(table_name, '.', column_name, ' ', collation_name) FROM information_schema.columns "
            . "WHERE table_schema = DATABASE() AND table_name IN ("
            . implode(', ', array_fill(0, count($views), '?'))
            . ") AND collation_name IS NOT NULL AND collation_name <> 'ascii_bin'"
        );
        $stmt->execute($views);

        $this->assertSame([], $stmt->fetchAll(PDO::FETCH_COLUMN));
    }

    public function test_migration_can_be_run_again(): void
    {
        $sql = file_get_contents(dirname(__DIR__, 2) . '/migrations/0005_mail_views.sql');
        $this->assertNotFalse($sql);

        $statements = SqlSplitter::split($sql);
        $this->assertNotSame([], $statements);
        foreach ($statements as $statement) {
            $this->pdo()->exec($statement);
        }

        $this->assertSame(['example.com', 'example.net'], $this->col('SELECT name FROM v_domains'));
    }

    // ---- v_domains, v_mailboxes, v_auth ------------------------------------------

    public function test_v_domains(): void
    {
        $this->assertSame(['example.com', 'example.net'], $this->col('SELECT name FROM v_domains'));
    }

    public function test_v_mailboxes(): void
    {
        $this->assertSame(
            ['alice@example.com', 'carol@example.com', 'dave@example.com'],
            $this->col('SELECT email FROM v_mailboxes')
        );
        $this->assertSame(
            'example.com/alice/',
            $this->pdo()->query("SELECT maildir FROM v_mailboxes WHERE email = 'alice@example.com'")->fetchColumn()
        );
    }

    public function test_v_mailboxes_quota(): void
    {
        $this->exec('UPDATE mailboxes SET quota_mb = 250 WHERE id = ?', [$this->carol]);

        $this->assertSame(
            250,
            (int) $this->pdo()->query("SELECT quota_mb FROM v_mailboxes WHERE email = 'carol@example.com'")->fetchColumn()
        );
    }

    public function test_v_auth_prefixes(): void
    {
        $this->assertStringStartsWith(
            '{ARGON2ID}$argon2id$',
            (string) $this->pdo()->query("SELECT password FROM v_auth WHERE email = 'alice@example.com'")->fetchColumn()
        );
        $this->assertStringStartsWith(
            '{BLF-CRYPT}$2y$',
            (string) $this->pdo()->query("SELECT password FROM v_auth WHERE email = 'carol@example.com'")->fetchColumn()
        );
        $this->assertSame([], $this->col("SELECT email FROM v_auth WHERE email = 'bob@example.com'"));
    }

    public function test_v_auth_returns_the_stored_hash_after_the_scheme(): void
    {
        $this->assertSame(
            ['{ARGON2ID}' . self::ARGON],
            $this->col("SELECT password FROM v_auth WHERE email = 'alice@example.com'")
        );
        $this->assertSame(
            ['{BLF-CRYPT}' . self::BCRYPT],
            $this->col("SELECT password FROM v_auth WHERE email = 'carol@example.com'")
        );
    }

    public function test_mailbox_views_leave_out_suspended_mailboxes_and_domains(): void
    {
        $expected = ['alice@example.com', 'carol@example.com', 'dave@example.com'];

        $this->assertSame($expected, $this->col('SELECT email FROM v_mailboxes'));
        $this->assertSame($expected, $this->col('SELECT email FROM v_auth'));
    }

    // ---- v_aliases ---------------------------------------------------------------

    public function test_alias_targets(): void
    {
        $this->assertSame(['alice@example.com', 'dave@example.com'], $this->destinations('sales@example.com'));
    }

    public function test_mailbox_without_forwarding_maps_to_itself(): void
    {
        $this->assertSame(['alice@example.com'], $this->destinations('alice@example.com'));
    }

    public function test_forwarding_without_copy(): void
    {
        $this->assertSame(['carol@gmail.com'], $this->destinations('carol@example.com'));
    }

    public function test_forwarding_with_copy(): void
    {
        $this->assertSame(
            ['dave@example.com', 'dave@gmail.com'],
            $this->destinations('dave@example.com')
        );
    }

    public function test_alias_to_suspended_mailbox_does_not_reach_another_user(): void
    {
        $this->alias($this->example, 'help', ['bob@example.com']);

        // help@ still maps to bob, who is not a mailbox Dovecot knows, so delivery bounces.
        $this->assertSame(['bob@example.com'], $this->destinations('help@example.com'));
        $this->assertSame(['help@example.com'], $this->destinations('help@example.net'));
        $this->assertSame([], $this->col("SELECT email FROM v_mailboxes WHERE email = 'bob@example.com'"));

        // Postfix looks bob@ up again after expanding help@; that must find nothing, and no
        // row anywhere may send mail meant for bob or help to another user.
        $this->assertSame([], $this->destinations('bob@example.com'));
        $this->assertSame([], $this->destinations('bob@example.net'));
        $this->assertSame(
            [],
            $this->col(
                "SELECT destination FROM v_aliases WHERE source LIKE 'help@%' AND destination = 'alice@example.com'"
            )
        );
        $this->assertSame([], $this->col("SELECT source FROM v_aliases WHERE source LIKE '@%'"));
        $this->assertSame([], $this->logins('help@example.com'));
    }

    public function test_suspended_mailbox_has_no_alias_rows(): void
    {
        $this->assertSame([], $this->col("SELECT source FROM v_aliases WHERE source = 'bob@example.com'"));
        $this->assertSame([], $this->col("SELECT source FROM v_aliases WHERE destination LIKE 'bob@%'"));
    }

    public function test_list_expansion_only_active_members(): void
    {
        $this->assertSame(['alice@example.com'], $this->destinations('team@example.com'));
        $this->assertSame([], $this->col("SELECT source FROM v_aliases WHERE source = 'old@example.com'"));
    }

    public function test_alias_domain_rows(): void
    {
        $this->assertSame(['alice@example.com'], $this->destinations('alice@example.net'));
        $this->assertSame(['sales@example.com'], $this->destinations('sales@example.net'));
        $this->assertSame(['team@example.com'], $this->destinations('team@example.net'));
        $this->assertSame([], $this->col("SELECT source FROM v_aliases WHERE source = 'bob@example.net'"));
        $this->assertSame([], $this->col("SELECT source FROM v_aliases WHERE source LIKE '%@other.net'"));
    }

    public function test_alias_domain_rows_are_exactly_the_target_local_addresses(): void
    {
        $this->assertSame(
            ['alice@example.net', 'carol@example.net', 'dave@example.net', 'sales@example.net', 'team@example.net'],
            $this->col("SELECT source FROM v_aliases WHERE source LIKE '%@example.net'")
        );
    }

    // ---- an alias domain with the name of a real domain --------------------------

    /**
     * b.com is a real domain and also listed as an alias of example.com. The real domain wins:
     * mail for b.com must never be copied or routed into example.com.
     */
    public function test_real_domain_beats_an_alias_domain_of_the_same_name(): void
    {
        $b = $this->domain('b.com');
        $this->mailbox($b, 'bob');
        $this->aliasDomain('b.com', $this->example);
        // Give example.com a live bob too, so an alias-domain row bob@b.com > bob@example.com could exist.
        $this->exec('UPDATE mailboxes SET status = ? WHERE id = ?', ['active', $this->bob]);

        $this->assertSame(['b.com', 'example.com', 'example.net'], $this->col('SELECT name FROM v_domains'));
        $this->assertSame(['bob@b.com'], $this->destinations('bob@b.com'));
        $this->assertSame([], $this->destinations('alice@b.com'));
        $this->assertSame(
            ['bob@b.com > bob@b.com'],
            $this->col("SELECT CONCAT(source, ' > ', destination) FROM v_aliases WHERE source LIKE '%@b.com'")
        );
    }

    public function test_rejections_of_the_target_never_reach_a_real_domain_of_the_same_name(): void
    {
        $b = $this->domain('b.com');
        $this->mailbox($b, 'alice');
        $this->mailbox($b, 'bob');
        $this->aliasDomain('b.com', $this->example);
        $this->exec('UPDATE mailboxes SET status = ? WHERE id = ?', ['suspended', $this->alice]);

        // alice and bob are suspended at example.com, but their b.com namesakes are live mailboxes.
        $this->assertSame([], $this->col("SELECT email FROM v_rejected_recipients WHERE email LIKE '%@b.com'"));
        $this->assertContains('alice@example.com mailbox_inactive', $this->rejected());
        $this->assertContains('alice@example.net mailbox_inactive', $this->rejected());
    }

    public function test_suspended_real_domain_still_beats_an_alias_domain_of_the_same_name(): void
    {
        $b = $this->domain('b.com', 'suspended');
        $this->mailbox($b, 'bob');
        $this->aliasDomain('b.com', $this->example);

        $this->assertSame(['example.com', 'example.net'], $this->col('SELECT name FROM v_domains'));
        $this->assertSame([], $this->col("SELECT source FROM v_aliases WHERE source LIKE '%@b.com'"));
        $this->assertSame([], $this->col("SELECT email FROM v_rejected_recipients WHERE email LIKE '%@b.com'"));
    }

    public function test_aliases_view_is_complete(): void
    {
        $rows = $this->pdo()->query(
            "SELECT CONCAT(source, ' > ', destination) FROM v_aliases"
        )->fetchAll(PDO::FETCH_COLUMN);
        sort($rows, SORT_STRING);

        $this->assertSame([
            'alice@example.com > alice@example.com',
            'alice@example.net > alice@example.com',
            'carol@example.com > carol@gmail.com',
            'carol@example.net > carol@example.com',
            'dave@example.com > dave@example.com',
            'dave@example.com > dave@gmail.com',
            'dave@example.net > dave@example.com',
            'sales@example.com > alice@example.com',
            'sales@example.com > dave@example.com',
            'sales@example.net > sales@example.com',
            'team@example.com > alice@example.com',
            'team@example.net > team@example.com',
        ], $rows);
    }

    // ---- forwarding rules and the identity row -----------------------------------

    public function test_mailbox_with_two_active_rules_keeps_a_copy_when_any_rule_asks_for_it(): void
    {
        $this->forward($this->carol, 'carol@yahoo.com', true);

        $this->assertSame(
            ['carol@example.com', 'carol@gmail.com', 'carol@yahoo.com'],
            $this->destinations('carol@example.com')
        );
    }

    public function test_inactive_rule_is_ignored(): void
    {
        $this->exec('UPDATE forwarding_rules SET active = 0 WHERE mailbox_id = ?', [$this->carol]);

        $this->assertSame(['carol@example.com'], $this->destinations('carol@example.com'));
    }

    public function test_inactive_rule_with_keep_copy_does_not_keep_a_copy(): void
    {
        $this->forward($this->carol, 'carol@yahoo.com', true);
        $this->exec(
            'UPDATE forwarding_rules SET active = 0 WHERE mailbox_id = ? AND destination = ?',
            [$this->carol, 'carol@yahoo.com']
        );

        $this->assertSame(['carol@gmail.com'], $this->destinations('carol@example.com'));
    }

    public function test_rules_of_a_mailbox_on_a_suspended_domain_are_ignored(): void
    {
        $this->forward($this->erin, 'erin@gmail.com', false);

        $this->assertSame([], $this->col("SELECT destination FROM v_aliases WHERE source LIKE 'erin@%'"));
    }

    // ---- aliases -----------------------------------------------------------------

    public function test_inactive_alias_is_ignored_everywhere(): void
    {
        $this->exec("UPDATE aliases SET active = 0 WHERE local_part = 'sales'");

        $this->assertSame([], $this->destinations('sales@example.com'));
        $this->assertSame([], $this->destinations('sales@example.net'));
        $this->assertSame([], $this->logins('sales@example.com'));
    }

    public function test_alias_on_a_suspended_domain_is_ignored(): void
    {
        $this->alias($this->other, 'info', ['erin@other.org']);

        $this->assertSame([], $this->col("SELECT source FROM v_aliases WHERE source LIKE '%@other.org'"));
        $this->assertSame([], $this->col("SELECT sender FROM v_sender_login WHERE sender LIKE '%@other.org'"));
    }

    public function test_alias_may_point_outside_the_hosted_domains(): void
    {
        $this->alias($this->example, 'press', ['editor@news.example']);

        $this->assertSame(['editor@news.example'], $this->destinations('press@example.com'));
        $this->assertSame(['press@example.com'], $this->destinations('press@example.net'));
    }

    // ---- lists -------------------------------------------------------------------

    public function test_list_with_every_member_suspended_has_no_rows(): void
    {
        $this->exec('UPDATE list_members SET status = ? WHERE list_id = ?', ['suspended', $this->team]);

        $this->assertSame([], $this->destinations('team@example.com'));
    }

    public function test_list_expansion_lists_every_active_member(): void
    {
        $this->member($this->team, $this->carol);
        $this->exec('UPDATE list_members SET status = ? WHERE list_id = ? AND mailbox_id = ?', ['active', $this->team, $this->dave]);

        $this->assertSame(
            ['alice@example.com', 'carol@example.com', 'dave@example.com'],
            $this->destinations('team@example.com')
        );
    }

    public function test_list_on_a_suspended_domain_is_ignored(): void
    {
        $list = $this->mailList($this->other, 'news');
        $this->member($list, $this->erin);

        $this->assertSame([], $this->col("SELECT source FROM v_aliases WHERE source LIKE 'news@%'"));
    }

    // ---- v_sender_login ----------------------------------------------------------

    public function test_v_sender_login(): void
    {
        $this->assertSame(['alice@example.com'], $this->logins('alice@example.com'));
        $this->assertSame(['alice@example.com', 'dave@example.com'], $this->logins('sales@example.com'));
        $this->assertSame([], $this->col("SELECT login FROM v_sender_login WHERE sender LIKE 'bob@%'"));
    }

    public function test_v_sender_login_is_complete(): void
    {
        $rows = $this->pdo()->query(
            "SELECT CONCAT(sender, ' < ', login) FROM v_sender_login"
        )->fetchAll(PDO::FETCH_COLUMN);
        sort($rows, SORT_STRING);

        $this->assertSame([
            'alice@example.com < alice@example.com',
            'carol@example.com < carol@example.com',
            'dave@example.com < dave@example.com',
            'sales@example.com < alice@example.com',
            'sales@example.com < dave@example.com',
        ], $rows);
    }

    public function test_v_sender_login_only_names_active_local_mailboxes(): void
    {
        $this->alias($this->example, 'ops', ['bob@example.com', 'erin@other.org', 'carol@example.com', 'outsider@gmail.com']);

        $this->assertSame(['carol@example.com'], $this->logins('ops@example.com'));
    }

    // ---- suspension takes effect at once -----------------------------------------

    public function test_suspension_is_immediate(): void
    {
        $this->exec('UPDATE mailboxes SET status = ? WHERE id = ?', ['suspended', $this->alice]);

        $this->assertSame([], $this->col("SELECT email FROM v_auth WHERE email = 'alice@example.com'"));
        $this->assertSame([], $this->col("SELECT email FROM v_mailboxes WHERE email = 'alice@example.com'"));
        $this->assertSame([], $this->col("SELECT source FROM v_aliases WHERE source = 'alice@example.com'"));
    }

    public function test_deleting_mailbox_counts_as_not_active(): void
    {
        $this->exec('UPDATE mailboxes SET status = ? WHERE id = ?', ['deleting', $this->dave]);

        $this->assertSame([], $this->col("SELECT email FROM v_auth WHERE email = 'dave@example.com'"));
        $this->assertSame([], $this->col("SELECT email FROM v_mailboxes WHERE email = 'dave@example.com'"));
        $this->assertSame([], $this->col("SELECT source FROM v_aliases WHERE source = 'dave@example.com'"));
        $this->assertSame(['alice@example.com'], $this->logins('sales@example.com'));
        $this->assertSame([], $this->logins('dave@example.com'));
    }

    public function test_domain_suspension_is_immediate(): void
    {
        $this->exec('UPDATE domains SET status = ? WHERE id = ?', ['suspended', $this->example]);

        $this->assertSame([], $this->col('SELECT name FROM v_domains'));
        $this->assertSame([], $this->col('SELECT email FROM v_mailboxes'));
        $this->assertSame([], $this->col('SELECT email FROM v_auth'));
        $this->assertSame([], $this->col('SELECT source FROM v_aliases'));
        $this->assertSame([], $this->col('SELECT sender FROM v_sender_login'));
        $this->assertSame([], $this->col('SELECT local_part FROM v_local_addresses'));
    }

    public function test_deleting_domain_counts_as_not_active(): void
    {
        $this->exec('UPDATE domains SET status = ? WHERE id = ?', ['deleting', $this->example]);

        $this->assertSame([], $this->col('SELECT name FROM v_domains'));
        $this->assertSame([], $this->col('SELECT source FROM v_aliases'));
    }

    public function test_reactivating_a_domain_brings_its_rows_back(): void
    {
        $this->exec('UPDATE domains SET status = ? WHERE id = ?', ['active', $this->other]);

        $this->assertSame(['example.com', 'example.net', 'other.net', 'other.org'], $this->col('SELECT name FROM v_domains'));
        $this->assertSame(['erin@other.org'], $this->destinations('erin@other.org'));
        $this->assertSame(['erin@other.org'], $this->destinations('erin@other.net'));
        $this->assertSame(
            ['alice@example.com', 'erin@other.org'],
            $this->destinations('team@example.com')
        );
    }

    public function test_list_suspension_is_immediate(): void
    {
        $this->exec('UPDATE lists SET status = ? WHERE id = ?', ['suspended', $this->team]);

        $this->assertSame([], $this->col("SELECT source FROM v_aliases WHERE source LIKE 'team@%'"));
    }

    public function test_member_suspension_is_immediate(): void
    {
        $this->exec('UPDATE list_members SET status = ? WHERE list_id = ? AND mailbox_id = ?', ['suspended', $this->team, $this->alice]);

        $this->assertSame([], $this->destinations('team@example.com'));
    }

    // ---- v_local_addresses -------------------------------------------------------

    public function test_v_local_addresses_is_mailboxes_aliases_and_lists_of_active_domains(): void
    {
        $rows = $this->pdo()->query(
            "SELECT CONCAT(d.name, '/', la.local_part) FROM v_local_addresses la JOIN domains d ON d.id = la.domain_id"
        )->fetchAll(PDO::FETCH_COLUMN);
        sort($rows, SORT_STRING);

        $this->assertSame([
            'example.com/alice',
            'example.com/carol',
            'example.com/dave',
            'example.com/sales',
            'example.com/team',
        ], $rows);
    }

    public function test_v_local_addresses_has_each_address_once(): void
    {
        $this->alias($this->example, 'alice', ['dave@example.com']);

        $this->assertSame(
            ['alice'],
            $this->col("SELECT local_part FROM v_local_addresses WHERE local_part = 'alice'")
        );
    }

    // ---- v_rejected_recipients ---------------------------------------------------

    public function test_v_rejected_recipients(): void
    {
        // Only bob (suspended mailbox) and old (suspended list), each also at example.net.
        // Nothing for other.org or other.net (suspended domain), and no row for the
        // addresses that deliver: alice, carol, dave, sales and team.
        $this->assertSame(
            ['bob@example.com', 'bob@example.net', 'old@example.com', 'old@example.net'],
            $this->col('SELECT email FROM v_rejected_recipients')
        );
        $this->assertSame(
            [
                'bob@example.com mailbox_inactive',
                'bob@example.net mailbox_inactive',
                'old@example.com list_inactive',
                'old@example.net list_inactive',
            ],
            $this->rejected()
        );
    }

    public function test_rejected_recipients_never_have_alias_rows(): void
    {
        $overlap = $this->pdo()->query(
            'SELECT COUNT(*) FROM v_rejected_recipients r JOIN v_aliases a ON a.source = r.email'
        )->fetchColumn();

        $this->assertSame(0, (int) $overlap);
    }

    public function test_rejected_recipients_leave_out_a_suspended_domain(): void
    {
        $this->mailbox($this->other, 'frank', 'suspended');
        $this->alias($this->other, 'info', []);
        $this->mailList($this->other, 'news', 'domain', 'suspended');

        $this->assertSame([], $this->col("SELECT email FROM v_rejected_recipients WHERE email LIKE '%@other.%'"));

        $this->exec('UPDATE domains SET status = ? WHERE id = ?', ['suspended', $this->example]);
        $this->assertSame([], $this->rejected());
    }

    public function test_deleting_mailbox_is_rejected(): void
    {
        $this->exec('UPDATE mailboxes SET status = ? WHERE id = ?', ['deleting', $this->dave]);

        $this->assertContains('dave@example.com mailbox_inactive', $this->rejected());
        $this->assertContains('dave@example.net mailbox_inactive', $this->rejected());
    }

    public function test_alias_without_targets_is_rejected(): void
    {
        $this->alias($this->example, 'nobody', []);

        $this->assertSame(
            ['nobody@example.com alias_empty', 'nobody@example.net alias_empty'],
            array_values(array_filter($this->rejected(), static fn (string $r): bool => str_starts_with($r, 'nobody@')))
        );
    }

    public function test_disabled_alias_is_rejected(): void
    {
        $this->exec("UPDATE aliases SET active = 0 WHERE local_part = 'sales'");

        $rows = array_values(array_filter($this->rejected(), static fn (string $r): bool => str_starts_with($r, 'sales@')));
        $this->assertSame(['sales@example.com alias_inactive', 'sales@example.net alias_inactive'], $rows);
    }

    public function test_disabled_alias_without_targets_gets_one_row(): void
    {
        $id = $this->alias($this->example, 'ghost', []);
        $this->exec('UPDATE aliases SET active = 0 WHERE id = ?', [$id]);

        $this->assertSame(
            ['ghost@example.com'],
            $this->col("SELECT email FROM v_rejected_recipients WHERE email LIKE 'ghost@%.com'")
        );
        $this->assertSame(
            ['alias_inactive'],
            $this->col("SELECT reason FROM v_rejected_recipients WHERE email = 'ghost@example.com'")
        );
    }

    public function test_list_with_only_suspended_members_is_rejected_as_empty(): void
    {
        $this->exec('UPDATE list_members SET status = ? WHERE list_id = ?', ['suspended', $this->team]);

        $this->assertContains('team@example.com list_empty', $this->rejected());
        $this->assertContains('team@example.net list_empty', $this->rejected());
    }

    public function test_list_whose_members_are_all_unable_to_receive_is_rejected_as_empty(): void
    {
        // alice was the only deliverable member: bob is suspended, dave's row is suspended
        // and erin's domain is suspended.
        $this->exec('UPDATE mailboxes SET status = ? WHERE id = ?', ['suspended', $this->alice]);

        $this->assertContains('team@example.com list_empty', $this->rejected());
        $this->assertContains('alice@example.com mailbox_inactive', $this->rejected());
    }

    public function test_list_without_members_is_rejected_as_empty(): void
    {
        $this->mailList($this->example, 'fresh');

        $this->assertContains('fresh@example.com list_empty', $this->rejected());
        $this->assertContains('fresh@example.net list_empty', $this->rejected());
    }

    public function test_suspended_list_is_inactive_even_when_it_has_no_members(): void
    {
        $this->mailList($this->example, 'quiet', 'domain', 'suspended');

        $this->assertContains('quiet@example.com list_inactive', $this->rejected());
    }

    public function test_alias_domain_of_a_suspended_domain_is_not_rejected(): void
    {
        $this->assertSame([], $this->col("SELECT email FROM v_rejected_recipients WHERE email LIKE '%@other.net'"));
    }

    public function test_address_in_several_states_gets_one_row(): void
    {
        // bob is a suspended mailbox; the same address as a disabled alias is a second reason.
        $id = $this->alias($this->example, 'bob', ['alice@example.com']);
        $this->exec('UPDATE aliases SET active = 0 WHERE id = ?', [$id]);

        $this->assertSame(
            ['alias_inactive'],
            $this->col("SELECT reason FROM v_rejected_recipients WHERE email = 'bob@example.com'")
        );
        $this->assertSame(
            ['bob@example.com', 'bob@example.net', 'old@example.com', 'old@example.net'],
            $this->col('SELECT email FROM v_rejected_recipients')
        );

        // The helper view already has one row per local part.
        $this->assertSame(
            ['alias_inactive'],
            $this->col(
                'SELECT reason FROM v_rejected_local WHERE domain_id = ? AND local_part = ?',
                [$this->example, 'bob']
            )
        );
    }

    public function test_rejected_recipients_change_immediately(): void
    {
        $this->exec('UPDATE mailboxes SET status = ? WHERE id = ?', ['active', $this->bob]);
        $this->assertSame(['old@example.com', 'old@example.net'], $this->col('SELECT email FROM v_rejected_recipients'));

        $this->exec('UPDATE lists SET status = ? WHERE id = ?', ['active', $this->old]);
        $this->assertSame([], $this->col('SELECT email FROM v_rejected_recipients'));

        $this->exec('UPDATE mailboxes SET status = ? WHERE id = ?', ['suspended', $this->carol]);
        $this->assertSame(
            ['carol@example.com', 'carol@example.net'],
            $this->col('SELECT email FROM v_rejected_recipients')
        );
    }

    public function test_reactivating_bob_removes_his_rows(): void
    {
        $this->exec('UPDATE mailboxes SET status = ? WHERE id = ?', ['active', $this->bob]);

        $this->assertSame(
            [],
            $this->col("SELECT email FROM v_rejected_recipients WHERE email LIKE 'bob@%'")
        );
        $this->assertSame(['bob@example.com'], $this->col("SELECT email FROM v_mailboxes WHERE email LIKE 'bob@%'"));
    }
}
