# Step 1 — Schema, Views, DB Users, Migrations: Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build the MariaDB schema, the mail-service views, the five least-privilege DB users, and `mailhostctl migrate` / `migrate:status` / `db:users`, so that migrations apply cleanly twice and every grant is verified.

**Architecture:** Plain SQL migration files are applied in order by a small PHP migrator that records a checksum for each file. Mail services see only SQL views, and those views already filter out suspended rows. DB users are provisioned from a grants table defined in code. Re-provisioning revokes everything and re-grants, so it is safe to repeat.

**Tech Stack:** PHP 8.3 CLI, PDO MySQL, MariaDB 10.11, Composer, PHPUnit 11 (Ubuntu 24.04 packages).

**Spec:** `docs/superpowers/specs/2026-10-31-mailhost-design.md` (§5 data model, §14 step 1).

## Global Constraints

- **Location:** repo root is `/home/claude/vps-mail`. All PHP lives under `app/`, with namespace `Mailhost\` (PSR-4 → `app/src/`). Every file starts with `declare(strict_types=1);`.
- **Database:** name `mailhost`, `utf8mb4` / `utf8mb4_unicode_ci`, InnoDB.
- **Identifiers:** domain names, local parts, email addresses, hashes and tokens use `CHARACTER SET ascii COLLATE ascii_bin` and must be lowercase, enforced by `CHECK (col = LOWER(col))`. Callers lowercase before lookup; Postfix does this itself, and Dovecot will use `%Lu` in step 2.
- **Times are UTC:** columns are `DATETIME`, and every connection runs `SET time_zone = '+00:00'`.
- **PDO:** `ERRMODE_EXCEPTION`, `EMULATE_PREPARES => false`.
- **Migrations are re-runnable:**
  - use `CREATE TABLE IF NOT EXISTS`, `CREATE OR REPLACE VIEW` and `INSERT IGNORE`;
  - a statement ends at a `;` at the end of a line;
  - no triggers or stored procedures.
- **Migrations are append-only:** never edit an applied file; add a new one.
- **Integration tests run only against a disposable MariaDB.** They create server-wide users (`mail_ro`, `mail_policy`, `mail_app`, `mail_portal`, `mailctl`). Connection details come from `MAILHOST_TEST_DB_HOST`, `MAILHOST_TEST_DB_PORT` and `MAILHOST_TEST_DB_ROOT_PASSWORD`, and the test database is `mailhost_test`.
- **Refinements to spec §5.1 and §5.3, decided here:**
  - The global filter policy lives in a single-row `filter_global` table, and `filter_policies` holds per-domain rows only. This avoids NULL-key uniqueness, and CHECKs on columns of a cascading FK.
  - `mail_policy` reads dedicated views (`v_lists`, `v_list_sender_rules`, `v_login_roles`) plus `settings`, instead of raw list tables.
  - `mail_portal` inserts jobs only through `v_portal_deployments`. `WITH CHECK OPTION` limits those jobs to `doveadm_kick`.
  - `mailctl` also gets INSERT on `quarantine_items` and `dkim_keys`, and DELETE on `mailboxes` and `domains`, for the archive jobs.

## Review Focus

1. **Mail for a suspended or empty address must never reach another user.** Catch-all aliases are not supported (Ruling 13), and `v_rejected_recipients` rejects non-active addresses at RCPT. Pinned in Task 4: `test_alias_to_suspended_mailbox_does_not_reach_another_user`, `test_v_rejected_recipients`.
2. **Suspended mailbox with a forwarding rule:** forwarding must stop. Pinned in Task 4: `test_suspended_mailbox_has_no_alias_rows`.
3. **Universal-list member whose own domain is suspended:** they must stop receiving list mail. Pinned in Task 4: `test_list_expansion_only_active_members`.
4. **Mixed-case address stored** (e.g. `Bob@Example.com`): lowercase lookups from Postfix would silently miss it, so inserts are rejected. Pinned in Task 3: `test_identifiers_must_be_lowercase`.
5. **Re-running `db:users` after a password rotation, or after someone added a grant by hand:** the old password must stop working and stray grants must disappear. Pinned in Task 6: `test_reprovision_rotates_password`, `test_reprovision_removes_stray_grants`.

---

### Task 1: Scaffold, `EnvFile`, `SqlSplitter`

**Files:**
- Create: `app/composer.json`, `app/phpunit.xml`, `app/.gitignore` (`vendor/`)
- Create: `app/src/Cli/EnvFile.php`, `app/src/Db/SqlSplitter.php`
- Test: `app/tests/Unit/EnvFileTest.php`, `app/tests/Unit/SqlSplitterTest.php`

**Interfaces:**
- Produces:
  - `Mailhost\Cli\EnvFile::load(string $path): array<string,string>`: throws `RuntimeException`.
  - `Mailhost\Db\SqlSplitter::split(string $sql): list<string>`: throws `InvalidArgumentException`.

- [ ] **Step 1: Install the toolchain on the dev VM.** Run `sudo apt-get install -y php8.3-cli php8.3-mysql php8.3-xml php8.3-mbstring composer mariadb-server`. Check that `php -v` shows 8.3 and `mariadb --version` shows 10.11.
- [ ] **Step 2: Create `composer.json` and `phpunit.xml`.**
  - `composer.json`: `require`: `php >=8.3`, `ext-pdo_mysql`. `require-dev`: `phpunit/phpunit ^11`. PSR-4 `Mailhost\\` → `src/`. Scripts: `test:unit` → `phpunit --testsuite unit`; `test:integration` → `phpunit --testsuite integration`.
  - `phpunit.xml`: two suites, `unit` (`tests/Unit`) and `integration` (`tests/Integration`).
  - Run `composer install`.
- [ ] **Step 3: Write the failing tests.**

```php
// SqlSplitterTest
test_splits_on_semicolon_at_line_end: split("CREATE TABLE a (x INT);\nCREATE TABLE b (y INT);\n")
    === ['CREATE TABLE a (x INT)', 'CREATE TABLE b (y INT)']
test_keeps_multiline_statement: count(split("CREATE VIEW v AS\nSELECT 1\nUNION ALL\nSELECT 2;\n")) === 1
test_strips_line_comments: split("-- note;\nSELECT 1;\n") === ['SELECT 1']
test_semicolon_inside_line_is_kept: split("INSERT INTO s VALUES ('a;b');\n") === ["INSERT INTO s VALUES ('a;b')"]
test_unterminated_statement_throws: split("SELECT 1") throws InvalidArgumentException /Unterminated statement/

// EnvFileTest (temp files created with chmod 0600 unless stated)
test_parses_pairs: "A=1\n# c\n\nB = two \nC=\"q v\"\n" → ['A'=>'1','B'=>'two','C'=>'q v']
test_rejects_world_readable: chmod 0644 → RuntimeException /world-readable/
test_rejects_malformed_line: "A=1\nNOVALUE\n" → RuntimeException /line 2/
test_missing_file_throws: RuntimeException /not found/
```

- [ ] **Step 4: Run the tests.** `cd app && composer test:unit` → FAIL (classes not found).
- [ ] **Step 5: Implement both classes.**
  - `SqlSplitter`: drop lines whose trimmed text starts with `--`. Collect lines into the current statement, and end it on a line whose right-trimmed text ends in `;`.
  - `EnvFile`: `fileperms($path) & 0o004` means the file is world-readable, so reject it. Keys must match `/^[A-Z][A-Z0-9_]*$/`.
- [ ] **Step 6: Run the tests.** `composer test:unit` → PASS.
- [ ] **Step 7: Commit.** `git commit -m "feat(db): scaffold app, env file loader, SQL splitter"`

---

### Task 2: `Connection`, `Migrator`, `mailhostctl migrate`

**Files:**
- Create: `app/src/Db/Connection.php`, `app/src/Db/Migrator.php`, `app/src/Db/MigrationException.php`, `app/bin/mailhostctl` (executable, `#!/usr/bin/env php`)
- Create: `app/migrations/.gitkeep`
- Test: `app/tests/Integration/DbTestCase.php`, `app/tests/Integration/MigratorTest.php`, `app/tests/Integration/MailhostctlTest.php`

**Interfaces:**
- Consumes: `EnvFile::load`, `SqlSplitter::split`.
- Produces:
  - `Connection::root(array $env, bool $withDb = true): PDO`. Uses `DB_HOST` + `DB_PORT` + `DB_ROOT_PASSWORD` if `DB_HOST` is set; otherwise `DB_SOCKET` (default `/run/mysqld/mysqld.sock`) as `DB_ROOT_USER` (default `root`). Database comes from `DB_NAME` (default `mailhost`).
  - `Connection::asUser(array $env, string $user, string $password): PDO`: TCP to `DB_HOST` (default `127.0.0.1`).
  - `Connection::ensureDatabase(PDO $rootNoDb, string $db): void`: `CREATE DATABASE IF NOT EXISTS … CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci`. `$db` must match `/^[a-z0-9_]+$/`.
  - `Migrator::__construct(PDO $pdo, string $dir)`.
  - `Migrator::status(): array<string,'applied'|'pending'>`, keyed by version, e.g. `0001_core_tables`.
  - `Migrator::migrate(): list<string>`, returning the versions applied.
  - Bookkeeping table: `schema_migrations(version VARCHAR(255) ascii_bin PK, checksum CHAR(64) ascii_bin, applied_at DATETIME)`, created by the Migrator.
  - Migration files must match `/^\d{4}_[a-z0-9_]+\.sql$/`; others are ignored. The checksum is `hash_file('sha256')`.
  - `DbTestCase` (abstract, extends `TestCase`): `rootPdo(): PDO`, `env(): array` (built from the `MAILHOST_TEST_*` variables, `DB_NAME=mailhost_test`), `freshDatabase(): void` (drop and recreate `mailhost_test`), `migrateAll(): void` (runs `app/migrations`).
  - CLI: `mailhostctl migrate | migrate:status | db:users`. Env file comes from `MAILHOST_DB_ENV` (default `/etc/mailhost/db.env`); the migrations folder from `MAILHOST_MIGRATIONS_DIR` (default `app/migrations`). Exit codes: 0 on success, 1 on error with a message on stderr.

- [ ] **Step 1: Write the failing tests.**

```php
// MigratorTest (each test gets a fresh DB and a temp migrations dir)
test_applies_pending_in_order_and_records: files 0002_b.sql, 0001_a.sql → migrate() === ['0001_a','0002_b'];
    schema_migrations has both, checksum === hash_file('sha256', …)
test_second_run_applies_nothing: migrate(); migrate() === []
test_changed_applied_file_is_refused: migrate(); add 0003_c.sql; edit 0001_a.sql →
    migrate() throws MigrationException /0001_a.*checksum/; 0003_c not recorded
test_missing_applied_file_is_refused: migrate(); unlink 0001_a.sql → throws /0001_a.*missing/
test_failed_statement_is_not_recorded: 0001_a.sql = "CREATE TABLE ok (x INT);\nNOT SQL;\n" →
    throws /0001_a.*statement 2/; status()['0001_a'] === 'pending'; fix the file → migrate() === ['0001_a']
test_ignores_non_migration_files: README.md and 1_bad.sql present → status() has only the valid versions

// MailhostctlTest (runs bin/mailhostctl via proc_open, env file chmod 0600)
test_cli_migrate_twice: DB absent → 1st run exit 0, stdout has "Applied: 0001_a"; 2nd run exit 0, stdout "Nothing to migrate."
test_cli_status: after migrate → stdout line "0001_a  applied"
test_cli_bad_env_exits_1: env chmod 0644 → exit 1, stderr /world-readable/
```

- [ ] **Step 2: Run the tests.** `composer test:integration -- --filter 'Migrator|Mailhostctl'` → FAIL.
- [ ] **Step 3: Implement `Connection`, `Migrator` and `MigrationException`.**
  - Check every applied checksum before running anything.
  - Run each statement with `PDO::exec`. On failure, throw with the version and the 1-based statement number.
  - Record the version only after all of its statements succeed.
- [ ] **Step 4: Implement `bin/mailhostctl`.**
  - Dispatch on `$argv[1]`.
  - `migrate` calls `ensureDatabase` first, then prints `Applied: <v>` for each version, or `Nothing to migrate.`.
  - `db:users` prints `Not implemented` and exits 1 for now (Task 6 fills it in).
- [ ] **Step 5: Run the tests.** → PASS.
- [ ] **Step 6: Commit.** `git commit -m "feat(db): migrator and mailhostctl migrate"`

---

### Task 3: Table migrations 0001–0004 with seed data

**Files:**
- Create: `app/migrations/0001_core_tables.sql`, `0002_lists.sql`, `0003_rbac.sql`, `0004_ops.sql`
- Test: `app/tests/Integration/SchemaTest.php`

**Interfaces:**
- Produces the 23 base tables (spec §5.1 plus `filter_global`), with the exact columns below. "id" means `INT UNSIGNED AUTO_INCREMENT PRIMARY KEY`. `lc` means an ascii_bin column with the lowercase CHECK. `FK→x (C)` means a foreign key with `ON DELETE CASCADE`; `(N)` means `SET NULL`; `(R)` means `RESTRICT`.

| File | Table | Columns and constraints |
|---|---|---|
| 0001 | `domains` | id; `name` VARCHAR(253) lc UNIQUE, also `REGEXP '^[a-z0-9]([a-z0-9.-]*[a-z0-9])?$'`; `status` ENUM(active,suspended,deleting) DEFAULT active; `default_quota_mb` INT UNSIGNED DEFAULT 1024; `max_mailboxes` INT UNSIGNED NULL; `external_forwarding` ENUM(inherit,deny) DEFAULT inherit; `suspended_at` NULL; `created_at` DEFAULT CURRENT_TIMESTAMP |
| 0001 | `domain_aliases` | id; `alias_domain` VARCHAR(253) lc UNIQUE; `target_domain_id` FK→domains (C) |
| 0001 | `dkim_keys` | id; `domain_id` FK→domains (C); `selector` VARCHAR(63) lc `REGEXP '^[a-z0-9-]+$'`; `public_key` TEXT; `active` BOOL DEFAULT 0; `created_at`; UNIQUE(domain_id, selector) |
| 0001 | `mailboxes` | id; `domain_id` FK→domains (C); `local_part` VARCHAR(64) lc `REGEXP '^[a-z0-9._+-]+$'`; UNIQUE(domain_id, local_part); `password_hash` VARCHAR(255) ascii_bin, CHECK `LIKE '$argon2id$%' OR LIKE '$2y$%'`; `recovery_email` VARCHAR(254) lc NULL; `recovery_verified_at` NULL; `status` ENUM(active,suspended,deleting) DEFAULT active; `quota_mb` INT UNSIGNED DEFAULT 1024; `quota_used_bytes` BIGINT UNSIGNED NULL; `usage_updated_at` NULL; `external_forwarding` ENUM(inherit,deny) DEFAULT inherit; `password_changed_at` DEFAULT CURRENT_TIMESTAMP; `suspended_at` NULL; `created_at` |
| 0001 | `aliases` | id; `domain_id` FK→domains (C); `local_part` VARCHAR(64) lc NOT NULL, CHECK <> '' (no catch-all aliases — Ruling 13); `active` BOOL DEFAULT 1; UNIQUE(domain_id, local_part) |
| 0001 | `alias_targets` | id; `alias_id` FK→aliases (C); `destination` VARCHAR(254) lc, CHECK `LIKE '_%@_%'`; UNIQUE(alias_id, destination) |
| 0001 | `forwarding_rules` | id; `mailbox_id` FK→mailboxes (C); `destination` as in alias_targets; `keep_copy` BOOL DEFAULT 1; `active` BOOL DEFAULT 1; `created_by_type` ENUM(admin,mailbox); `created_by_id` INT UNSIGNED; `created_at`; UNIQUE(mailbox_id, destination) |
| 0002 | `lists` | id; `domain_id` FK→domains (C); `local_part` VARCHAR(64) lc, CHECK <> ''; `scope` ENUM(domain,universal); `self_subscribe` BOOL DEFAULT 0; `max_message_kb` INT UNSIGNED NULL (NULL means the global limit); `status` ENUM(active,suspended) DEFAULT active; `created_at`; UNIQUE(domain_id, local_part) |
| 0002 | `list_members` | `list_id` FK→lists (C); `mailbox_id` FK→mailboxes (C); `status` ENUM(active,suspended) DEFAULT active; `added_at`; PK(list_id, mailbox_id) |
| 0002 | `list_owners` | `list_id` FK (C); `mailbox_id` FK (C); PK(list_id, mailbox_id) |
| 0002 | `list_sender_rules` | id; `list_id` FK (C); `rule_type` ENUM(address,domain,role,any_authenticated); `value` VARCHAR(254) lc DEFAULT ''; CHECK `(rule_type='any_authenticated') = (value='')`; UNIQUE(list_id, rule_type, value) |
| 0003 | `roles` | id; `name` VARCHAR(32) ascii_bin UNIQUE |
| 0003 | `role_permissions` | `role_id` FK→roles (C); `permission` VARCHAR(64) ascii_bin; PK(role_id, permission) |
| 0003 | `admins` | id; `username` VARCHAR(64) ascii_bin UNIQUE `REGEXP '^[a-z0-9._-]{3,64}$'`; `email` VARCHAR(254) lc; `password_hash` (same CHECK as mailboxes); `role_id` FK→roles (R); `mailbox_id` FK→mailboxes (N) NULL; `status` ENUM(active,suspended) DEFAULT active; `last_login_at` NULL; `created_at` |
| 0003 | `admin_domains` | `admin_id` FK (C); `domain_id` FK (C); `may_manage_universal_members` BOOL DEFAULT 0; PK(admin_id, domain_id) |
| 0004 | `filter_global` | `id` TINYINT UNSIGNED PK DEFAULT 1, CHECK `id = 1`; `tag_score`, `quarantine_score`, `reject_score` DECIMAL(5,2); `virus_action` ENUM(reject,quarantine) DEFAULT reject; `unscannable_action` ENUM(quarantine,tag,reject) DEFAULT quarantine; `bound_min_score`, `bound_max_score` DECIMAL(5,2) NOT NULL; CHECK `tag_score <= quarantine_score AND quarantine_score <= reject_score`; CHECK `bound_min_score <= bound_max_score` |
| 0004 | `filter_policies` | `domain_id` PK, FK→domains (C); `tag_score`, `quarantine_score`, `reject_score` DECIMAL(5,2); `virus_action` ENUM(reject,quarantine) DEFAULT reject; `unscannable_action` ENUM(quarantine,tag,reject) DEFAULT quarantine; CHECK `tag_score <= quarantine_score AND quarantine_score <= reject_score`. The app enforces the global bounds on save. |
| 0004 | `quarantine_items` | id; `queue_id` VARCHAR(32) ascii_bin UNIQUE; `domain_id` FK (C) NULL; `envelope_from` VARCHAR(254) ascii_bin; `envelope_to` TEXT; `score` DECIMAL(6,2); `reason` VARCHAR(1024); `size_bytes` INT UNSIGNED; `held_at`; `status` ENUM(held,released,deleted) DEFAULT held |
| 0004 | `otp_codes` | `id` BIGINT UNSIGNED AI PK; `subject_type` ENUM(mailbox,admin); `subject_id` INT UNSIGNED; `purpose` ENUM(login,recovery,verify_email); `code_hmac` CHAR(64) ascii_bin; `target` VARCHAR(254) lc NULL; `expires_at`; `attempts` TINYINT UNSIGNED DEFAULT 0; `used_at` NULL; `request_ip` VARCHAR(45); `created_at`; INDEX(subject_type, subject_id, purpose) |
| 0004 | `sessions` | `token_hash` CHAR(64) ascii_bin PK; `subject_type` ENUM(admin,mailbox); `subject_id` INT UNSIGNED; `created_at`; `last_seen_at`; `expires_at`; `ip` VARCHAR(45); `user_agent` VARCHAR(255); `revoked_at` NULL; INDEX(subject_type, subject_id) |
| 0004 | `audit_log` | `id` BIGINT UNSIGNED AI PK; `at` DATETIME(3) DEFAULT CURRENT_TIMESTAMP(3); `actor_type` ENUM(admin,mailbox,system,anonymous); `actor_id` INT UNSIGNED NULL; `action` VARCHAR(64); `target_type` VARCHAR(32) NULL; `target_id` VARCHAR(255) NULL; `domain_id` INT UNSIGNED NULL (no FK, so history survives deletes); `ip` VARCHAR(45) NULL; `details` JSON NULL; INDEX(at), INDEX(domain_id, at), INDEX(actor_type, actor_id) |
| 0004 | `deployments` | `id` BIGINT UNSIGNED AI PK; `job_type` ENUM(dkim_generate,rspamd_policy,doveadm_kick,quarantine_release,quarantine_delete,domain_archive,mailbox_archive,retention_sweep); `payload` JSON NOT NULL; `status` ENUM(queued,running,applied,failed,rolled_back) DEFAULT queued; `requested_by_type` ENUM(admin,mailbox,system); `requested_by_id` INT UNSIGNED NULL; `created_at`; `finished_at` NULL; `log` MEDIUMTEXT NULL; INDEX(status, id) |
| 0004 | `settings` | `key` VARCHAR(64) ascii_bin PK; `value` VARCHAR(255) NOT NULL |

**Seed data (all `INSERT IGNORE`):**
- **roles:** `super_admin`, `domain_admin`.
- **super_admin permissions:** `domain.manage, domain.view, mailbox.manage, alias.manage, forwarding.manage, list.domain.manage, list.universal.manage, filter.global.manage, filter.domain.manage, quarantine.manage, admin.manage, audit.read, system.configure`.
- **domain_admin permissions:** `domain.view, mailbox.manage, alias.manage, forwarding.manage, list.domain.manage, filter.domain.manage, audit.read`.
- **settings:** `otp_ttl_minutes=10, otp_max_attempts=5, external_forwarding=allow, superadmin_list_override=allow, retention_suspended_days=30, retention_archive_days=90, max_message_mb=25`.
- **`filter_global` row:** tag 6.00, quarantine 10.00, reject 15.00, virus `reject`, unscannable `quarantine`, bounds 4.00–25.00.

- [ ] **Step 1: Write the failing tests** (`SchemaTest`; `setUp` → `freshDatabase(); migrateAll();`).

```php
test_all_base_tables_exist: information_schema BASE TABLEs of mailhost_test minus schema_migrations
    === the 23 names above (sorted)
test_identifiers_must_be_lowercase: INSERT domains name 'Example.com' → PDOException errorInfo[1] === 4025;
    INSERT mailbox local_part 'Bob' → 4025
test_password_hash_prefix_enforced: 'plain' → 4025; '$argon2id$v=19$m=65536,t=4,p=1$x$y' ok; '$2y$10$abc' ok
test_duplicate_mailbox_rejected: same (domain, local_part) twice → errorInfo[1] === 1062
test_deleting_domain_cascades: domain A with mailbox, alias+target, forwarding, domain list+member, dkim key,
    admin_domains row; universal list U in domain B with A's mailbox as member →
    DELETE domain A → zero child rows for A; U still exists with 0 members
test_admin_mailbox_link_set_null: delete linked mailbox → admins.mailbox_id IS NULL
test_filter_policy_rules: INSERT filter_global id=2 → 4025; 2nd filter_policies row for the same domain → 1062;
    tag 16 > reject 15 → 4025 (in both tables)
test_sender_rule_value_rules: any_authenticated + 'x' → 4025; address + '' → 4025
test_seeds: exact role permission sets above; settings === the 7 pairs above; global policy values above
test_migrations_rerunnable: DELETE FROM schema_migrations; migrateAll() → no exception;
    role_permissions count === 20; settings count === 7; filter_global count === 1
```

- [ ] **Step 2: Run the tests.** `composer test:integration -- --filter SchemaTest` → FAIL.
- [ ] **Step 3: Write `0001`–`0004`** to match the table above, in FK order, using `IF NOT EXISTS` everywhere.
- [ ] **Step 4: Run the tests.** → PASS.
- [ ] **Step 5: Commit.** `git commit -m "feat(db): core, list, rbac and ops tables with seeds"`

---

### Task 4: Mail-service views (`0005_mail_views.sql`)

**Files:**
- Create: `app/migrations/0005_mail_views.sql`
- Test: `app/tests/Integration/MailViewsTest.php`, `app/tests/Integration/Fixtures.php` (trait)

**Interfaces:**
- Consumes: the Task 3 tables.
- Produces the following views. "Active" means the row's status is `active`, its domain's status is `active`, and for aliases and rules `active = 1`.
  - `v_domains(name)`: active domains, plus `alias_domain` values whose target domain is active.
  - `v_local_addresses(domain_id, local_part)`: internal helper, never granted. Union of active mailboxes, active aliases and active lists.
  - `v_mailboxes(email, maildir, quota_mb)`: active mailboxes; `maildir = CONCAT(domain, '/', local_part, '/')`.
  - `v_auth(email, password)`: active mailboxes. `password` is `CONCAT('{ARGON2ID}', hash)` when the hash starts with `$argon2id$`, otherwise `CONCAT('{BLF-CRYPT}', hash)`.
  - `v_aliases(source, destination)`: UNION ALL of
    - (a) alias targets, with source `CONCAT(local_part, '@', domain)`;
    - (b) each active forwarding rule of an active mailbox → its destination;
    - (c) **identity row** mailbox → itself, when the mailbox is active AND (it has no active rules OR any active rule has `keep_copy = 1`);
    - (d) list → member, for an active list, an active member row, and a member mailbox that is active (which means the member's own domain is active too);
    - (e) for each alias domain with an active target: `lp@alias_domain → lp@target` for every `v_local_addresses` row in the target domain.
  - `v_sender_login(sender, login)`: each active mailbox → itself; each active alias address → each target that is an active local mailbox.
  - `v_rejected_recipients(email, reason)` (Ruling 11, added in fix round): in active domains, (1) non-active mailboxes, (2) lists that are not active or have no deliverable member, (3) non-catch-all aliases that are inactive or have no targets; plus (4) their `lp@alias_domain` variants for alias domains with an active target. Step 2 wires it as Postfix `check_recipient_access`, so these addresses are rejected instead of falling through to a catch-all.
  - Fixture helpers in the `Fixtures` trait:
    - `domain(string $name, string $status = 'active'): int`
    - `aliasDomain(string $alias, int $targetId): void`
    - `mailbox(int $domainId, string $lp, string $status = 'active', string $hash = ARGON): int`
    - `alias(int $domainId, string $lp, array $destinations): int`
    - `forward(int $mailboxId, string $dest, bool $keepCopy): void`
    - `mailList(int $domainId, string $lp, string $scope = 'domain', string $status = 'active', ?int $maxKb = null): int`
    - `member(int $listId, int $mailboxId, string $status = 'active'): void`
    - `col(string $sql, array $params = []): list<string>` (first column of every row, sorted).

- [ ] **Step 1: Write the failing tests.**

  **Shared fixture:**
  - Domains: `example.com` (active) and `other.org` (suspended).
  - Alias domains: `example.net → example.com` and `other.net → other.org`.
  - Mailboxes:
    - alice@example.com: active, argon2id;
    - bob@example.com: **suspended**, with a forward to bob@gmail.com;
    - carol@example.com: active, `$2y$`, forward to carol@gmail.com with keep_copy=0;
    - dave@example.com: active, forward to dave@gmail.com with keep_copy=1;
    - erin@other.org: active (but her domain is suspended).
  - Aliases: `sales@example.com → alice@example.com, dave@example.com`.
  - Lists:
    - universal `team@example.com` with members alice (active), bob (active row, but his mailbox is suspended), dave (member row suspended) and erin (active row, but her domain is suspended);
    - `old@example.com` with status suspended and member alice.

```php
test_v_domains: col(name) === ['example.com','example.net']
test_v_mailboxes: emails === [alice, carol, dave]@example.com; alice maildir === 'example.com/alice/'
test_v_auth_prefixes: alice starts '{ARGON2ID}$argon2id$'; carol starts '{BLF-CRYPT}$2y$'; bob absent
test_alias_targets: destinations of 'sales@example.com' === ['alice@example.com','dave@example.com']
test_mailbox_without_forwarding_maps_to_itself: destinations of 'alice@example.com' === ['alice@example.com']
test_forwarding_without_copy: of 'carol@example.com' === ['carol@gmail.com']
test_forwarding_with_copy: of 'dave@example.com' === ['dave@example.com','dave@gmail.com']
test_suspended_mailbox_has_no_alias_rows: no row with source 'bob@example.com'
test_list_expansion_only_active_members: of 'team@example.com' === ['alice@example.com']; no row for 'old@example.com'
test_alias_domain_rows: 'alice@example.net' → ['alice@example.com']; 'sales@example.net' → ['sales@example.com'];
    'team@example.net' → ['team@example.com']; no 'bob@example.net'; nothing from other.net
test_v_sender_login: 'alice@example.com' → ['alice@example.com'];
    'sales@example.com' → ['alice@example.com','dave@example.com']; no 'bob@…'; no '@example.com'
test_suspension_is_immediate: UPDATE mailboxes SET status='suspended' WHERE alice →
    alice absent from v_auth, v_mailboxes and as a source in v_aliases (same connection, no other action)
```

- [ ] **Step 2: Run the tests.** `--filter MailViewsTest` → FAIL.
- [ ] **Step 3: Write `0005_mail_views.sql`** (`CREATE OR REPLACE VIEW`, in dependency order: `v_local_addresses` first).
- [ ] **Step 4: Run the tests.** → PASS.
- [ ] **Step 5: Commit.** `git commit -m "feat(db): mail-service views"`

---

### Task 5: Policy and portal views (`0006_policy_views.sql`)

**Files:**
- Create: `app/migrations/0006_policy_views.sql`
- Test: `app/tests/Integration/PolicyViewsTest.php`

**Interfaces:**
- Consumes: the `Fixtures` trait from Task 4.
- Produces:
  - `v_lists(address, list_id, scope, max_message_kb)`: active lists in active domains. `max_message_kb = COALESCE(l.max_message_kb, (SELECT CAST(value AS UNSIGNED) * 1024 FROM settings WHERE `key` = 'max_message_mb'))`.
  - `v_list_sender_rules(address, rule_type, value)`: rules of the lists in `v_lists`.
  - `v_login_roles(login, role)`: active admins whose `mailbox_id` points to an active mailbox in an active domain → (mailbox email, role name).
  - `v_portal_deployments(id, job_type, payload, requested_by_type, requested_by_id)`: `SELECT … FROM deployments WHERE job_type = 'doveadm_kick' AND requested_by_type = 'mailbox' WITH CASCADED CHECK OPTION`.

- [ ] **Step 1: Write the failing tests.**

```php
test_v_lists_limits: list team (max NULL) → 25600; list big (max 512) → 512;
    suspended list absent; list in suspended domain absent
test_v_list_sender_rules: rules (any_authenticated,''), (domain,'example.com') on team → both rows by address
test_v_login_roles: active admin linked to alice, super_admin → [('alice@example.com','super_admin')];
    suspended admin absent; admin linked to suspended mailbox absent
test_portal_view_accepts_kick: INSERT INTO v_portal_deployments (job_type, payload, requested_by_type, requested_by_id)
    VALUES ('doveadm_kick','{"mailbox_id":1}','mailbox',1) → deployments row with status 'queued'
test_portal_view_rejects_other_jobs: job_type 'dkim_generate' → errorInfo[1] === 1369;
    requested_by_type 'admin' → 1369
```

- [ ] **Step 2: Run the tests.** → FAIL.
- [ ] **Step 3: Write `0006_policy_views.sql`.**
- [ ] **Step 4: Run the tests.** → PASS.
- [ ] **Step 5: Commit.** `git commit -m "feat(db): policy and portal views"`

---

### Task 6: Grants, `UserProvisioner`, `mailhostctl db:users`, end-to-end check

**Files:**
- Create: `app/src/Db/Grants.php`, `app/src/Db/UserProvisioner.php`
- Modify: `app/bin/mailhostctl` (implement `db:users`)
- Test: `app/tests/Unit/GrantsTest.php`, `app/tests/Integration/GrantsMatrixTest.php`

**Interfaces:**
- Consumes: `Connection::root`, `Connection::asUser`.
- Produces:
  - `Grants::USERS = ['mail_ro','mail_policy','mail_app','mail_portal','mailctl']`.
  - `Grants::TABLES`: the 23 base table names.
  - `Grants::forUser(string $user, string $db): list<string>`: statements without the `TO` clause, e.g. ``GRANT SELECT ON `mailhost`.`v_auth` ``.
  - `UserProvisioner::__construct(PDO $root, string $db, list<string> $hosts)`.
  - `UserProvisioner::provision(string $user, string $password): void`. For each host, in order:
    1. `CREATE USER IF NOT EXISTS`;
    2. `ALTER USER … IDENTIFIED BY <PDO::quote>`;
    3. `REVOKE ALL PRIVILEGES, GRANT OPTION FROM`;
    4. each `forUser` statement + ` TO 'u'@'h'`.
  - `UserProvisioner::provisionAll(array $passwordsByUser): void`.
  - Validation: `$user` must be in `USERS`, and the password must match `/^[A-Za-z0-9+\/=._~-]{24,128}$/`; otherwise throw `InvalidArgumentException`.
  - Env keys for `db:users`: `DB_PASS_MAIL_RO`, `DB_PASS_MAIL_POLICY`, `DB_PASS_MAIL_APP`, `DB_PASS_MAIL_PORTAL`, `DB_PASS_MAILCTL`, and `DB_USER_HOSTS` (default `localhost,127.0.0.1`).

**Grants table (exact):**

| User | Grants |
|---|---|
| `mail_ro` | SELECT on `v_domains`, `v_mailboxes`, `v_auth`, `v_aliases`, `v_sender_login`, `v_rejected_recipients` |
| `mail_policy` | SELECT on `v_domains`, `v_lists`, `v_list_sender_rules`, `v_login_roles`, `settings`; INSERT (`actor_type`, `actor_id`, `action`, `target_type`, `target_id`, `domain_id`, `ip`, `details`) on `audit_log` |
| `mail_app` | SELECT, INSERT, UPDATE, DELETE on every `TABLES` entry except `audit_log`; SELECT on `audit_log`; INSERT (`actor_type`, `actor_id`, `action`, `target_type`, `target_id`, `domain_id`, `ip`, `details`) on `audit_log` |
| `mail_portal` | SELECT on `domains`, `mailboxes`, `lists`, `list_owners`, `settings`; UPDATE (`password_hash`, `recovery_email`, `recovery_verified_at`, `password_changed_at`) on `mailboxes`; SELECT, INSERT, UPDATE, DELETE on `forwarding_rules`, `list_members`, `otp_codes`, `sessions`; INSERT (`job_type`, `payload`, `requested_by_type`, `requested_by_id`) on `v_portal_deployments` only (no SELECT/UPDATE/DELETE on it); INSERT (`actor_type`, `actor_id`, `action`, `target_type`, `target_id`, `domain_id`, `ip`, `details`) on `audit_log` |
| `mailctl` | SELECT on `` `db`.* ``; UPDATE on `deployments`; SELECT, INSERT, UPDATE on `quarantine_items`; UPDATE (`quota_used_bytes`, `usage_updated_at`) on `mailboxes`; INSERT, UPDATE on `dkim_keys`; DELETE on `mailboxes`, `domains`; INSERT (`actor_type`, `actor_id`, `action`, `target_type`, `target_id`, `domain_id`, `ip`, `details`) on `audit_log` |

- [ ] **Step 1: Write the failing tests.**

```php
// GrantsTest (unit)
test_users: Grants::USERS === the five names
test_no_dangerous_grants: no statement for any user contains '*.*', 'ALL PRIVILEGES' or 'GRANT OPTION';
    the only '`.*' statement is mailctl's 'GRANT SELECT ON `mailhost`.*'
test_mail_ro_reads_exactly_six_views: forUser('mail_ro','mailhost') === 6 statements, one per view above

// GrantsMatrixTest (integration; freshDatabase, migrateAll, provisionAll with random 32-char passwords,
// connect with Connection::asUser over 127.0.0.1)
test_tables_constant_matches_schema: Grants::TABLES sorted === information_schema base tables minus schema_migrations
#[DataProvider] test_matrix(user, sql, allowed): allowed → no exception;
    denied → PDOException with errorInfo[1] in [1142, 1143]
    mail_ro:     SELECT * FROM v_auth ✓ | SELECT * FROM mailboxes ✗ | SELECT * FROM v_lists ✗ | INSERT INTO audit_log … ✗
    mail_policy: SELECT * FROM v_list_sender_rules ✓ | SELECT * FROM settings ✓ | INSERT INTO audit_log … ✓
                 | SELECT * FROM v_auth ✗ | SELECT * FROM mailboxes ✗
    mail_app:    UPDATE mailboxes SET quota_mb=quota_mb ✓ | INSERT INTO audit_log … ✓ | UPDATE audit_log SET action='x' ✗
                 | DELETE FROM audit_log ✗ | SELECT * FROM schema_migrations ✗
    mail_portal: UPDATE mailboxes SET password_hash=password_hash ✓ | UPDATE mailboxes SET quota_mb=1 ✗
                 | SELECT * FROM admins ✗ | INSERT INTO deployments … ✗ | INSERT INTO v_portal_deployments (kick) ✓
                 | UPDATE audit_log SET action='x' ✗
    mailctl:     UPDATE deployments SET status=status ✓ | UPDATE mailboxes SET quota_used_bytes=0 ✓
                 | UPDATE mailboxes SET password_hash=password_hash ✗ | DELETE FROM domains WHERE name='gone.test' ✓
                 | INSERT INTO admins … ✗
test_column_level_inserts (Ruling 15/16): mail_portal INSERT INTO v_portal_deployments naming `id` → 1143;
    mail_portal SELECT/UPDATE/DELETE on v_portal_deployments → 1142; for every user with audit_log INSERT,
    INSERT naming `id` or `at` → 1143 while INSERT of the 8 allowed columns works
test_reprovision_rotates_password: provision('mail_ro', p1); provision('mail_ro', p2) →
    asUser(p1) throws errorInfo[1] === 1045; asUser(p2) works; SHOW GRANTS line count unchanged
test_reprovision_removes_stray_grants: root runs GRANT SELECT ON mailhost_test.mailboxes TO mail_ro@'127.0.0.1';
    provision('mail_ro', p) → SELECT * FROM mailboxes as mail_ro → 1142
test_rejects_bad_input: provision('root', valid) → InvalidArgumentException; provision('mail_ro','short') → InvalidArgumentException
test_cli_db_users: env with all 5 DB_PASS_* → exit 0, stdout has 10 lines 'Provisioned <user>@<host>';
    missing DB_PASS_MAILCTL → exit 1, stderr /DB_PASS_MAILCTL/
```

- [ ] **Step 2: Run the tests.** `composer test:unit && composer test:integration -- --filter Grants` → FAIL.
- [ ] **Step 3: Implement `Grants`, `UserProvisioner` and `mailhostctl db:users`.**
- [ ] **Step 4: Run the tests.** → PASS.
- [ ] **Step 5: End-to-end check against a scratch database `mailhost_e2e`.**
  1. `MAILHOST_DB_ENV=<tmp env, 0600> bin/mailhostctl migrate` → `Applied:` lines for 0001–0006.
  2. Run it again → `Nothing to migrate.`
  3. `bin/mailhostctl db:users` → 10 `Provisioned` lines.
  4. `bin/mailhostctl migrate:status` → six `applied` lines.
  5. `composer test:unit && composer test:integration` → all green.
- [ ] **Step 6: Commit.** `git commit -m "feat(db): least-privilege DB users and db:users command"`
