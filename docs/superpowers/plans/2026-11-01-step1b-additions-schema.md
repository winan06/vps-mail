# Step 1b — Schema for the Version 1 Additions: Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add the tables, columns, views and grants for the twelve version 1 additions in spec §17, so steps 2–8 can build on a tested schema.

**Architecture:** New migrations 0007–0014 sit on top of the reviewed 0001–0006 and never edit them. Existing tables change through re-runnable `ALTER`s; views change through `CREATE OR REPLACE`. Mail-routing and login behaviour (app passwords, 2FA, shared mailboxes, directory) lives in views with tests, as in step 1. The portal reaches every row type it must not cross (admin rows, other job types) only through `WITH CASCADED CHECK OPTION` views.

**Tech Stack:** PHP 8.3, MariaDB 10.11.14, PHPUnit 9.6.17 (Ubuntu package), offline Composer autoload — the same as step 1.

**Spec:** `docs/superpowers/specs/2026-10-31-mailhost-design.md` (§17, and §5 for the step 1 schema this builds on).

## Global Constraints

- **Same rules as step 1:** read and follow the step 1 plan's Global Constraints (`docs/superpowers/plans/2026-10-31-step1-schema.md`), and the conventions in `app/migrations/0001–0006`:
  - named `chk_*` / `fk_*` / `uq_*` / `ix_*` constraints;
  - `\\z`-anchored REGEXPs;
  - ascii_bin lowercase identifiers;
  - UTC `DATETIME`;
  - a statement ends at a `;` at the end of a line, and comments are whole lines only.
- **Never edit 0001–0006.** New files are `0007_…` through `0014_…`.
- **Re-runnable ALTERs:**
  - columns: `ALTER TABLE t ADD COLUMN IF NOT EXISTS …`, `MODIFY COLUMN …`;
  - CHECKs: `ALTER TABLE t DROP CONSTRAINT IF EXISTS c;` then `ALTER TABLE t ADD CONSTRAINT c CHECK (…);`, as two statements;
  - ENUM growth: `MODIFY COLUMN` with the full new list.
  - `SchemaTest::test_migrations_rerunnable` (glob-based) must stay green.
- **Shared address patterns** (reuse the exact step 1 regexes):
  - local part: `^[a-z0-9_+-]+(\\.[a-z0-9_+-]+)*\\z`;
  - domain: labels `[a-z0-9]([a-z0-9-]*[a-z0-9])?`, two or more, joined by dots;
  - address: local part `@` domain.
- **Free text** shown to users or written into Sieve/vCard (display name, job title, department, rule values, folder names, app password names): utf8mb4, never empty, no control characters (`NOT REGEXP '[[:cntrl:]]'`). Rule values and folder names also exclude `"` and `\`.
- **Encrypted secrets** (TOTP secret, migration password): `VARBINARY`. The app encrypts with a server key in steps 5/7; the schema only stores ciphertext.
- **No AUTO_INCREMENT wedge:** any user other than root that writes a table with an AUTO_INCREMENT `id` gets column-level INSERT/UPDATE grants that exclude `id`. The same rule as Rulings 15/16 in step 1.
- **Integration tests** run only against a disposable MariaDB (step 1's shared-server guard stays on).

## Review Focus

1. **2FA user's main password still opens IMAP.** `v_auth` must leave out mailboxes with `require_app_passwords = 1`. Test: `test_v_auth_excludes_app_password_only_mailboxes` (Task 5).
2. **Revoked app password, or one on a suspended mailbox/domain, still logs in.** Test: `test_v_app_auth_only_live_passwords` (Task 5).
3. **A shared mailbox gets a login, or a member from another domain or a suspended member gets access or send-as.** Tests: `test_shared_mailbox_has_no_credentials` (Task 2), `test_v_shared_acl_rules`, `test_v_sender_login_shared_senders` (Task 5).
4. **The portal creates admin 2FA secrets, recovery codes or login events, or queues a job for another mailbox.** Tests: `test_portal_totp_views_mailbox_only`, `test_portal_job_payload_must_match_requester` (Task 6).
5. **A Sieve rule value or folder name carries characters that break the generated script.** Test: `test_sieve_rule_text_rules` (Task 4).

---

### Task 1: Fixtures for the additions

**Files:**
- Modify: `app/tests/Integration/Fixtures.php`

**Interfaces:**
- Produces (each returns the new row id where there is one):
  - `sharedMailbox(int $domainId, string $lp, string $status = 'active'): int`, inserting `kind='shared'`, `password_hash NULL`, `recovery_email NULL`;
  - `appPassword(int $mailboxId, string $name, ?string $revokedAt = null): int`, with `password_hash = self::ARGON`;
  - `sharedAccess(int $sharedId, int $memberId, bool $canRead = true, bool $canSend = false): void`;
  - `setMailbox(int $id, array $columns): void`, a generic UPDATE for flags such as `require_app_passwords`, `directory_visible`, `display_name`.
- Consumes: the `kind`, `require_app_passwords` and similar columns from Task 2. Commit this task together with Task 2; it has no tests of its own.

- [ ] **Step 1:** Add the four helpers in the trait's existing style (prepared statements, `insertRow`).
- [ ] **Step 2:** Folded into Task 2's commit.

---

### Task 2: Mailbox and domain columns (`0007_mailbox_profile.sql`)

**Files:**
- Create: `app/migrations/0007_mailbox_profile.sql`
- Modify: `app/tests/Integration/SchemaTest.php`, `app/tests/Integration/Fixtures.php` (Task 1)

**Columns:**

| Table | Column | Type / rule |
|---|---|---|
| `mailboxes` | `display_name`, `job_title`, `department` | VARCHAR(128) utf8mb4 NULL, free-text rule (`chk_mailboxes_<col>_text`) |
| `mailboxes` | `phone` | VARCHAR(32) ascii NULL, `^\\+?[0-9][0-9 ().-]{2,30}\\z` |
| `mailboxes` | `directory_visible` | BOOL NOT NULL DEFAULT 1 |
| `mailboxes` | `kind` | ENUM('personal','shared') NOT NULL DEFAULT 'personal' |
| `mailboxes` | `require_app_passwords` | BOOL NOT NULL DEFAULT 0 |
| `mailboxes` | `quota_warned_level` | TINYINT UNSIGNED NOT NULL DEFAULT 0, CHECK ≤ 100 |
| `mailboxes` | `must_change_password` | BOOL NOT NULL DEFAULT 0 |
| `mailboxes` | `password_hash` | MODIFY to NULL-able (the existing prefix CHECK passes NULL) |
| `mailboxes` | — | `chk_mailboxes_kind_credentials`: `(kind='personal' AND password_hash IS NOT NULL) OR (kind='shared' AND password_hash IS NULL AND recovery_email IS NULL AND require_app_passwords = 0)` |
| `domains` | `mta_sts_mode` | ENUM('none','testing','enforce') NOT NULL DEFAULT 'testing' |

- [ ] **Step 1: Write the failing tests (SchemaTest).**

```php
test_new_mailbox_columns_and_defaults: information_schema shows each column above with its type, nullability and default
test_shared_mailbox_has_no_credentials: shared with a password → 4025 chk_mailboxes_kind_credentials;
    shared with recovery_email → 4025 (same); personal with NULL password → 4025 (same);
    sharedMailbox() fixture inserts fine
test_profile_text_rules (provider): display_name "" / "a\nb" / "a\tb" → 4025 chk_mailboxes_display_name_text;
    same for job_title and department; phone "abc" / "1" / "+265 99 123 4567\n" → 4025 chk_mailboxes_phone_format;
    valid: display_name 'Chikondi Banda', 'Zoë Ménard'; phone '+265 991 234 567', '(01) 234-5678'
test_quota_warned_level_bounds: 101 → 4025; 95 ok
test_existing_rows_get_defaults: a mailbox inserted by the step 1 fixture → kind 'personal', directory_visible 1,
    require_app_passwords 0, must_change_password 0
```

- [ ] **Step 2: Run** `composer test:integration -- --filter SchemaTest` → FAIL (unknown columns).
- [ ] **Step 3: Write `0007`** using the re-runnable ALTER patterns. Add Task 1's helpers.
- [ ] **Step 4: Run** SchemaTest and the full integration suite → PASS. Existing MailViewsTest/PolicyViewsTest must stay green (no view changes yet).
- [ ] **Step 5: Commit** `feat(db): mailbox profile, kind and security columns`

---

### Task 3: Login security and log tables (`0008_auth_security.sql`, `0009_activity_logs.sql`)

**Files:**
- Create: `app/migrations/0008_auth_security.sql`, `app/migrations/0009_activity_logs.sql`
- Modify: `app/tests/Integration/SchemaTest.php`

**Tables:**

| File | Table | Columns and constraints |
|---|---|---|
| 0008 | `app_passwords` | id; `mailbox_id` FK→mailboxes (C); `name` VARCHAR(64) utf8mb4 free-text; `password_hash` VARCHAR(255) ascii_bin CHECK `LIKE '$argon2id$%'`; `created_at`; `last_used_at` NULL; `revoked_at` NULL; ix(mailbox_id) |
| 0008 | `totp_secrets` | `subject_type` ENUM(mailbox,admin); `subject_id` INT UNSIGNED; `secret_enc` VARBINARY(255) NOT NULL; `confirmed_at` NULL; `last_used_step` BIGINT UNSIGNED NULL (replay guard); `created_at`; PK(subject_type, subject_id) |
| 0008 | `recovery_codes` | id; `subject_type` ENUM(mailbox,admin); `subject_id`; `code_hash` CHAR(64) ascii_bin lc; `used_at` NULL; `created_at`; uq(subject_type, subject_id, code_hash) |
| 0009 | `login_events` | `id` BIGINT AI; `at` DATETIME(3) DEFAULT CURRENT_TIMESTAMP(3); `subject_type` ENUM(mailbox,admin,unknown); `subject_id` NULL; `login` VARCHAR(254) utf8mb4 (as typed); `service` ENUM(imap,smtp,portal,admin,dav); `result` ENUM(ok,fail); `ip` VARCHAR(45) ascii; `country` CHAR(2) ascii NULL, CHECK `^[A-Z]{2}\\z`; `client` VARCHAR(255) utf8mb4 NULL; `app_password_id` FK→app_passwords (N) NULL; ix(subject_type, subject_id, at), ix(at), ix(ip, at) |
| 0009 | `delivery_events` | `id` BIGINT AI; `queue_id` VARCHAR(32) ascii; `at` DATETIME(3); `sender`, `recipient` VARCHAR(254) utf8mb4_bin, lowercase CHECK (empty sender allowed for bounces); `status` ENUM(sent,deferred,bounced,rejected,held,expired); `relay` VARCHAR(255) ascii NULL; `dsn` VARCHAR(16) ascii NULL; `reason` VARCHAR(255) utf8mb4 NULL; `sender_domain_id`, `recipient_domain_id` INT UNSIGNED NULL (no FK, so history survives deletes); ix(at), ix(sender, at), ix(recipient, at), ix(sender_domain_id, at), ix(recipient_domain_id, at), ix(queue_id) |
| 0009 | `log_cursors` | `source` VARCHAR(32) ascii_bin PK; `cursor_value` VARCHAR(512) ascii; `updated_at` |

- [ ] **Step 1: Write the failing tests (SchemaTest).**

```php
test_tables_exist: the base-table list now includes the 6 new tables (update SchemaTest::TABLES and the count)
test_app_password_rules: name "" / "a\nb" → 4025; bcrypt hash → 4025 (Argon2id only); mailbox delete cascades
test_totp_one_secret_per_subject: second row for (mailbox, 1) → 1062
test_recovery_code_rules: uppercase hex → 4025; duplicate (subject, code) → 1062
test_login_event_rules: country 'mw' → 4025, 'MW' ok; deleting a referenced app password sets app_password_id NULL
test_delivery_event_rules: uppercase recipient → 4025; empty sender ok; a delivery event survives deleting its domain
```

- [ ] **Step 2: Run** → FAIL. **Step 3: Write 0008 and 0009.** **Step 4: Run** SchemaTest and the full suite → PASS.
- [ ] **Step 5: Commit** `feat(db): app passwords, 2FA and activity log tables`

---

### Task 4: Mail feature, request and check tables (`0010`–`0012`)

**Files:**
- Create: `app/migrations/0010_mail_features.sql`, `0011_requests_checks.sql`, `0012_jobs_settings.sql`
- Modify: `app/tests/Integration/SchemaTest.php`

**Tables:**

| File | Table | Columns and constraints |
|---|---|---|
| 0010 | `sieve_rules` | id; `mailbox_id` FK (C); `position` SMALLINT UNSIGNED; `active` BOOL DEFAULT 1; `match_field` ENUM(from,to_cc,subject,header); `header_name` VARCHAR(64) ascii NULL, `^[A-Za-z0-9-]{1,64}\\z`, required iff match_field='header'; `match_type` ENUM(contains,is); `match_value` VARCHAR(255) utf8mb4, Sieve-text rule; `action` ENUM(move,mark_read,flag,trash,stop); `folder` VARCHAR(255) utf8mb4 NULL, Sieve-text rule plus not starting with `/`, required iff action='move' and NULL otherwise; uq(mailbox_id, position) |
| 0010 | `vacation_settings` | `mailbox_id` PK, FK (C); `enabled` BOOL DEFAULT 0; `starts_at`, `ends_at` NULL, CHECK `ends_at > starts_at` when both set; `subject` VARCHAR(255) utf8mb4 free-text; `body` TEXT utf8mb4, CHECK `CHAR_LENGTH(body) BETWEEN 1 AND 4096`; `interval_days` TINYINT UNSIGNED DEFAULT 7, CHECK 1–30; `time_zone` VARCHAR(64) ascii DEFAULT 'UTC', `^[A-Za-z_]+(/[A-Za-z0-9_+-]+)*\\z`; `updated_at` |
| 0010 | `spam_sender_lists` | id; `mailbox_id` FK (C); `list_type` ENUM(allow,block); `pattern` VARCHAR(254) ascii_bin lc, matching the address pattern OR `@` + domain pattern; uq(mailbox_id, pattern); `created_at` |
| 0010 | `shared_access` | `shared_mailbox_id` FK→mailboxes (C); `member_mailbox_id` FK→mailboxes (C); `can_read` BOOL DEFAULT 1; `can_send` BOOL DEFAULT 0; PK(shared, member); CHECK shared ≠ member. Same domain and the right kinds are enforced by the views (Task 5) and the app. |
| 0011 | `release_requests` | id; `quarantine_item_id` FK→quarantine_items (C); `mailbox_id` FK (C); `token_hash` CHAR(64) ascii_bin lc UNIQUE; `status` ENUM(offered,requested,approved,rejected,expired) DEFAULT offered; `requested_at`, `decided_at` NULL; `decided_by` FK→admins (N) NULL; `expires_at` |
| 0011 | `quota_requests` | id; `mailbox_id` FK (C); `requested_mb` INT UNSIGNED, CHECK > 0; `note` VARCHAR(500) utf8mb4 NULL; `status` ENUM(pending,approved,rejected) DEFAULT pending; `created_at`; `decided_at` NULL; `decided_by` FK→admins (N) NULL |
| 0011 | `domain_checks` | `domain_id` FK (C); `check_name` ENUM(mx,spf,dkim,dmarc,autoconfig,autodiscover,mta_sts,tls_rpt,ptr); `status` ENUM(ok,warn,fail); `detail` VARCHAR(500) utf8mb4; `checked_at`; PK(domain_id, check_name) |
| 0011 | `dmarc_reports` | id; `org_name` VARCHAR(255) utf8mb4; `report_id` VARCHAR(255) utf8mb4; uq(org_name, report_id); `policy_domain` VARCHAR(253) ascii_bin lc; `domain_id` INT UNSIGNED NULL (no FK); `date_begin`, `date_end`; `policy_p` ENUM(none,quarantine,reject) NULL; `received_at` |
| 0011 | `dmarc_records` | `id` BIGINT AI; `report_id` FK→dmarc_reports (C); `source_ip` VARCHAR(45) ascii; `count` INT UNSIGNED; `disposition` ENUM(none,quarantine,reject); `dkim_result`, `spf_result` VARCHAR(16) ascii; `header_from` VARCHAR(253) ascii_bin lc; ix(report_id) |
| 0011 | `migration_jobs` | id; `mailbox_id` FK (C); `host` VARCHAR(253) ascii lc, domain pattern or IPv4 `^([0-9]{1,3}\\.){3}[0-9]{1,3}\\z`; `port` SMALLINT UNSIGNED, CHECK 1–65535; `tls` ENUM(ssl,starttls) (no plaintext); `username` VARCHAR(254) utf8mb4 free-text; `password_enc` VARBINARY(512) NULL; `status` ENUM(queued,running,done,failed,cancelled) DEFAULT queued; CHECK `password_enc IS NULL` when status is done/failed/cancelled; `messages_total`, `messages_copied` INT UNSIGNED NULL; `error` VARCHAR(500) NULL; `created_by` FK→admins (N) NULL; `created_at`, `started_at`, `finished_at` NULL; `expires_at` |

0012 changes:
- `deployments.job_type` ENUM gains `domain_certs`, `sieve_compile`, `spam_lists`, `imap_migrate`, `domain_check`.
- `INSERT IGNORE` settings: `quota_warn_levels=80,90,95`, `admin_require_2fa=no`, `login_alert_new_country=yes`, `digest_hour_utc=6`, `login_events_retention_days=90`, `delivery_events_retention_days=30`, `dmarc_retention_days=180`.
- Note: `domain_check` is a small refinement of spec §17.13, for the "on demand" check in 17.10.

- [ ] **Step 1: Write the failing tests (SchemaTest).**

```php
test_tables_exist: +10 tables (now 39 base tables)
test_sieve_rule_text_rules (provider): match_value with '"' / '\' / "\n" / '' → 4025 (named check);
    folder '/x', 'a"b', "a\nb" → 4025; action move without folder → 4025; action flag with folder → 4025;
    match_field header without header_name → 4025; header_name 'X Spam' → 4025; valid rows insert
test_vacation_rules: ends_at before starts_at → 4025; body '' and 4097 chars → 4025; interval 0 / 31 → 4025;
    time_zone 'Africa/Blantyre' ok, 'x;y' → 4025
test_spam_pattern_rules: 'Bob@x.com', 'x.com', '@x', 'a,b@x.com' → 4025; 'bob@x.com', '@x.com' ok; duplicate → 1062
test_shared_access_self → 4025
test_migration_job_rules: port 0 → 4025; host 'Mail.Old.com' → 4025; status 'done' with password_enc set → 4025
test_job_types_and_settings: the 5 new job types insert; the 7 settings have the exact values above
test_migrations_rerunnable stays green with 0007–0012 present
```

- [ ] **Step 2: Run** → FAIL. **Step 3: Write 0010–0012.** **Step 4: Run** SchemaTest and the full suite → PASS.
- [ ] **Step 5: Commit** `feat(db): rules, out-of-office, spam lists, shared access, requests, checks, migrations`

---

### Task 5: Mail-service views for the additions (`0013_v1_mail_views.sql`)

**Files:**
- Create: `app/migrations/0013_v1_mail_views.sql`
- Modify: `app/tests/Integration/MailViewsTest.php` (and its `COLUMNS` list)

**Interfaces (views; "active" means as in step 1, mailbox and domain both active):**
- `v_auth(email, password)` — redefined. Same output as step 1, but only active **personal** mailboxes with `require_app_passwords = 0`.
- `v_app_auth(email, password, app_password_id)`:
  - one row per non-revoked app password of an active personal mailbox;
  - `password = CONCAT('{ARGON2ID}', hash)`.
  - Step 2 decides how Dovecot tries several rows per user (SQL passdb vs Lua). Record this in the migration comment.
- `v_sender_login(sender, login)` — redefined:
  - the mailbox → itself branch is limited to personal mailboxes;
  - the alias branch is unchanged;
  - new branch: shared address → member login, when `can_send = 1`, both active, same `domain_id`, shared `kind='shared'`, member `kind='personal'`.
- `v_shared_acl(shared_email, shared_maildir, member_login, rights)`:
  - rows only where `can_read = 1`, both active, same domain, right kinds;
  - `rights = 'lrwstie'` (constant, ascii_bin);
  - feeds Dovecot's shared dict, or the `dovecot-acl` files written by `mailctl-deploy`.
- `v_directory(domain, email, display_name, job_title, department, phone, kind)`:
  - active mailboxes (personal and shared) with `directory_visible = 1`;
  - `display_name` falls back to the local part when NULL.
- `v_mailboxes`, `v_aliases` and `v_rejected_*` are unchanged; shared mailboxes are already covered by them. Assert this with tests.

- [ ] **Step 1: Write the failing tests (MailViewsTest).**

Extra fixture: in example.com, shared `support` with members alice (read+send), carol (read only) and bob (suspended, read+send); erin@other.org (other domain) is given read+send to support; an app password each for alice (live) and dave (revoked); dave gets `require_app_passwords = 1`.

```php
test_v_auth_excludes_app_password_only_mailboxes: dave absent; alice, carol present; support absent
test_v_app_auth_only_live_passwords: alice's live password present with its id and {ARGON2ID} prefix;
    revoked one absent; alice suspended → absent; example.com suspended → absent
test_v_sender_login_shared_senders: 'support@example.com' → ['alice@example.com'] only
    (carol can't send, bob suspended, erin other domain); 'support@example.com' never maps to itself
test_v_shared_acl_rules: rows exactly alice and carol, rights 'lrwstie', maildir 'example.com/support/'
test_v_directory: visible active mailboxes incl. support with kind 'shared'; directory_visible=0 hides one;
    NULL display_name falls back to local part; suspended mailbox absent
test_shared_mailbox_receives_mail: support in v_mailboxes; support@ has no v_aliases rows; not in v_rejected_recipients
test_views_expose_exactly_the_documented_columns / test_every_text_column_is_ascii_bin: add the new views
    (v_directory's text columns are utf8mb4 by design — exclude it from the ascii test and say why in a comment)
```

- [ ] **Step 2: Run** → FAIL. **Step 3: Write 0013.** **Step 4: Run** MailViewsTest and the full suite → PASS (step 1 tests unchanged except added fixture rows).
- [ ] **Step 5: Commit** `feat(db): app-password auth, shared mailbox and directory views`

---

### Task 6: Portal views (`0014_v1_portal_views.sql`)

**Files:**
- Create: `app/migrations/0014_v1_portal_views.sql`
- Modify: `app/tests/Integration/PolicyViewsTest.php`

**Interfaces (all `WITH CASCADED CHECK OPTION`, all columns of the base table unless stated):**
- `v_portal_deployments` — redefined:
  - `job_type IN ('doveadm_kick','sieve_compile','spam_lists')`;
  - `requested_by_type = 'mailbox'`, `requested_by_id IS NOT NULL`;
  - `CAST(JSON_VALUE(payload, '$.mailbox_id') AS UNSIGNED) = requested_by_id`.
  - So the portal can only queue jobs for the mailbox it names as the requester.
- `v_portal_totp_secrets`, `v_portal_recovery_codes`: `subject_type = 'mailbox'`.
- `v_portal_login_events`: `subject_type IN ('mailbox','unknown') AND service IN ('portal','dav')`.

- [ ] **Step 1: Write the failing tests (PolicyViewsTest, as root through the views).**

```php
test_portal_job_payload_must_match_requester: sieve_compile with payload {"mailbox_id":5}, requested_by_id 5 → ok;
    requested_by_id 6 → 1369; payload without mailbox_id → 1369; dkim_generate → 1369; kick still works
test_portal_totp_views_mailbox_only: insert/replace/update subject_type 'admin' through v_portal_totp_secrets
    and v_portal_recovery_codes → 1369; admin rows invisible; mailbox rows round-trip
test_portal_login_events_scope: service 'imap' or 'admin' → 1369; subject_type 'admin' → 1369; admin rows invisible
test_portal_views_are_cascaded_and_updatable: the four views report CASCADED / YES
```

- [ ] **Step 2: Run** → FAIL. **Step 3: Write 0014.** **Step 4: Run** PolicyViewsTest and the full suite → PASS.
- [ ] **Step 5: Commit** `feat(db): portal views for 2FA, login events and per-mailbox jobs`

---

### Task 7: Grants for the additions, end-to-end check

**Files:**
- Modify: `app/src/Db/Grants.php`, `app/tests/Unit/GrantsTest.php`, `app/tests/Integration/GrantsMatrixTest.php`

**Interfaces:**
- `Grants::TABLES` covers all 39 base tables.
- New `Grants::APP_TABLES`: the tables `mail_app` gets full S/I/U/D on, which is every table except `audit_log`, `login_events`, `delivery_events`, `dmarc_reports`, `dmarc_records`, `domain_checks`, `log_cursors`, `schema_migrations`.
- "col-INSERT/UPDATE" below means column-level grants on every column except `id`.

**Grant additions (on top of step 1):**

| User | Adds |
|---|---|
| `mail_ro` | SELECT on `v_app_auth`, `v_shared_acl` (8 views total) |
| `mail_policy` | nothing |
| `mail_app` | S/I/U/D on the new APP_TABLES, except column-level INSERT/UPDATE without `id` on the new AUTO_INCREMENT tables; SELECT on `login_events`, `delivery_events`, `dmarc_reports`, `dmarc_records`, `domain_checks`; col-INSERT on `login_events` |
| `mail_portal` | UPDATE (`display_name`, `job_title`, `department`, `phone`, `directory_visible`, `require_app_passwords`, `must_change_password`) on `mailboxes`, added to its list. SELECT + INSERT (`mailbox_id`, `name`, `password_hash`) + UPDATE (`revoked_at`) on `app_passwords`. SELECT + INSERT + DELETE + UPDATE (`confirmed_at`, `last_used_step`) on `v_portal_totp_secrets`. SELECT + INSERT (`subject_type`, `subject_id`, `code_hash`) + UPDATE (`used_at`) + DELETE on `v_portal_recovery_codes`. SELECT + col-INSERT on `v_portal_login_events`. SELECT on `v_directory`, `shared_access`, `release_requests`, `quota_requests`. SELECT, DELETE, col-INSERT, col-UPDATE on `sieve_rules`, `spam_sender_lists`. S/I/U/D on `vacation_settings`. UPDATE (`status`, `requested_at`) on `release_requests`. col-INSERT (`mailbox_id`, `requested_mb`, `note`) on `quota_requests`. |
| `mailctl` | col-INSERT + DELETE on `login_events`, `delivery_events`; col-INSERT + DELETE on `dmarc_reports`; col-INSERT on `dmarc_records`; S/I/U/D on `domain_checks`, `log_cursors`; UPDATE (`quota_warned_level`) on `mailboxes`, added to its list; UPDATE (`last_used_at`) on `app_passwords`; INSERT (`quarantine_item_id`, `mailbox_id`, `token_hash`, `status`, `expires_at`) + UPDATE (`status`) on `release_requests`; UPDATE (`status`, `password_enc`, `messages_total`, `messages_copied`, `started_at`, `finished_at`, `error`) on `migration_jobs`; INSERT (`job_type`, `payload`, `requested_by_type`, `requested_by_id`) on `deployments` |

Never granted: `v_local_addresses`, `v_list_addresses`, `v_rejected_local`, `schema_migrations`. The portal never gets table grants on `totp_secrets`, `recovery_codes` or `login_events`.

- [ ] **Step 1: Write the failing tests.**

```php
// GrantsTest (unit): exact statements per user updated; test_mail_ro_reads_exactly_eight_views;
//   test_no_id_in_column_grants: for every user, no column-level INSERT/UPDATE list contains `id`;
//   test_portal_never_named_tables: no mail_portal statement names totp_secrets, recovery_codes, login_events, sessions, otp_codes
// GrantsMatrixTest (integration) — new matrix rows:
mail_ro:     SELECT * FROM v_app_auth ✓ | SELECT * FROM app_passwords ✗ | SELECT * FROM v_directory ✗
mail_portal: UPDATE mailboxes SET display_name='X' ✓ | UPDATE mailboxes SET kind='shared' ✗ | UPDATE mailboxes SET quota_warned_level=0 ✗
             INSERT INTO app_passwords (mailbox_id,name,password_hash) … ✓ | INSERT naming id ✗ | UPDATE app_passwords SET password_hash=… ✗
             SELECT * FROM totp_secrets ✗ | SELECT * FROM v_portal_totp_secrets ✓ | SELECT * FROM login_events ✗
             INSERT INTO sieve_rules naming id ✗ | DELETE FROM sieve_rules ✓ | SELECT * FROM v_directory ✓ | SELECT * FROM migration_jobs ✗
mailctl:     INSERT INTO login_events (…no id) ✓ | INSERT naming id ✗ | UPDATE migration_jobs SET password_enc=NULL ✓
             UPDATE migration_jobs SET host='x.com' ✗ | INSERT INTO deployments (job_type,…) ✓ | UPDATE app_passwords SET revoked_at=NOW() ✗
mail_app:    SELECT * FROM delivery_events ✓ | DELETE FROM delivery_events ✗ | INSERT INTO login_events naming id ✗
test_tables_constant_matches_schema stays green (39)
```

- [ ] **Step 2: Run** `composer test:unit && composer test:integration -- --filter Grants` → FAIL.
- [ ] **Step 3: Implement** the additions in `Grants.php`, keeping the step 1 shape (pure data, one private method per user, `_` escaped only in mailctl's `.*` statement).
- [ ] **Step 4: Run** → PASS.
- [ ] **Step 5: End-to-end check** on a scratch database `mailhost_e2e`, the same way as step 1:
  1. `migrate` → `Applied:` lines for 0001–0014.
  2. Run again → `Nothing to migrate.`
  3. `db:users` → 10 `Provisioned` lines.
  4. `migrate:status` → 14 `applied` lines.
  5. Full unit + integration suites green, with `Max_used_connections` reported.
  6. Drop the scratch database.
- [ ] **Step 6: Commit** `feat(db): least-privilege grants for the version 1 additions`
