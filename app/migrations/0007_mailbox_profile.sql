-- 0007: directory profile, mailbox kind and security flags (spec 17.1, 17.5, 17.8, 17.9, 17.10, 17.11).
--
-- Rules for 0007 to 0014, on top of those in 0001:
--   * 0001 to 0006 are never edited. Existing tables change here through statements that are
--     safe to run again: ADD COLUMN IF NOT EXISTS, MODIFY COLUMN with the full definition, and
--     a CHECK is replaced by DROP CONSTRAINT IF EXISTS followed by ADD CONSTRAINT.
--   * Free text that people read, or that ends up in a Sieve script or a vCard, is utf8mb4,
--     never empty and has no control characters (NOT REGEXP '[[:cntrl:]]'), so a value cannot
--     add a line to a generated file.
--
-- Columns added to mailboxes:
--   display_name, job_title, department  directory fields (17.1), free text, NULL when unset.
--   phone                 digits with an optional leading + and an optional ( before the
--                         first digit, then digits, spaces and ( ) . - only.
--   directory_visible     1 lists the mailbox in v_directory (0013), 0 hides it.
--   kind                  'personal' logs in, 'shared' never does (17.8).
--   require_app_passwords 1 once 2FA is on: v_auth (0013) then leaves the main password out.
--   quota_warned_level    the highest warning threshold already sent, in percent (17.9).
--   must_change_password  forces a new password at the next portal login (17.11).
-- password_hash becomes NULL-able, for shared mailboxes only (chk_mailboxes_kind_credentials).
-- The existing chk_mailboxes_password_hash_prefix passes NULL.

ALTER TABLE mailboxes MODIFY COLUMN password_hash VARCHAR(255) CHARACTER SET ascii COLLATE ascii_bin NULL;

ALTER TABLE mailboxes ADD COLUMN IF NOT EXISTS display_name VARCHAR(128) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci NULL;

ALTER TABLE mailboxes ADD COLUMN IF NOT EXISTS job_title VARCHAR(128) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci NULL;

ALTER TABLE mailboxes ADD COLUMN IF NOT EXISTS department VARCHAR(128) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci NULL;

ALTER TABLE mailboxes ADD COLUMN IF NOT EXISTS phone VARCHAR(32) CHARACTER SET ascii COLLATE ascii_bin NULL;

ALTER TABLE mailboxes ADD COLUMN IF NOT EXISTS directory_visible BOOL NOT NULL DEFAULT 1;

ALTER TABLE mailboxes ADD COLUMN IF NOT EXISTS kind ENUM('personal', 'shared') NOT NULL DEFAULT 'personal';

ALTER TABLE mailboxes ADD COLUMN IF NOT EXISTS require_app_passwords BOOL NOT NULL DEFAULT 0;

ALTER TABLE mailboxes ADD COLUMN IF NOT EXISTS quota_warned_level TINYINT UNSIGNED NOT NULL DEFAULT 0;

ALTER TABLE mailboxes ADD COLUMN IF NOT EXISTS must_change_password BOOL NOT NULL DEFAULT 0;

ALTER TABLE mailboxes DROP CONSTRAINT IF EXISTS chk_mailboxes_display_name_text;

ALTER TABLE mailboxes ADD CONSTRAINT chk_mailboxes_display_name_text CHECK (display_name <> '' AND display_name NOT REGEXP '[[:cntrl:]]');

ALTER TABLE mailboxes DROP CONSTRAINT IF EXISTS chk_mailboxes_job_title_text;

ALTER TABLE mailboxes ADD CONSTRAINT chk_mailboxes_job_title_text CHECK (job_title <> '' AND job_title NOT REGEXP '[[:cntrl:]]');

ALTER TABLE mailboxes DROP CONSTRAINT IF EXISTS chk_mailboxes_department_text;

ALTER TABLE mailboxes ADD CONSTRAINT chk_mailboxes_department_text CHECK (department <> '' AND department NOT REGEXP '[[:cntrl:]]');

ALTER TABLE mailboxes DROP CONSTRAINT IF EXISTS chk_mailboxes_phone_format;

ALTER TABLE mailboxes ADD CONSTRAINT chk_mailboxes_phone_format CHECK (phone REGEXP '^\\+?\\(?[0-9][0-9 ().-]{2,29}\\z');

ALTER TABLE mailboxes DROP CONSTRAINT IF EXISTS chk_mailboxes_quota_warned_level_range;

ALTER TABLE mailboxes ADD CONSTRAINT chk_mailboxes_quota_warned_level_range CHECK (quota_warned_level <= 100);

-- A personal mailbox always has a password. A shared mailbox has no password, no recovery
-- email and no app-password flag, so nothing can ever log in as it: members reach it through
-- shared_access (0010) and the views of 0013.
ALTER TABLE mailboxes DROP CONSTRAINT IF EXISTS chk_mailboxes_kind_credentials;

ALTER TABLE mailboxes ADD CONSTRAINT chk_mailboxes_kind_credentials CHECK (
    (kind = 'personal' AND password_hash IS NOT NULL)
    OR (kind = 'shared' AND password_hash IS NULL AND recovery_email IS NULL AND require_app_passwords = 0)
);

-- MTA-STS policy mode served at https://mta-sts.<domain>/ (17.10). New domains start in testing.
ALTER TABLE domains ADD COLUMN IF NOT EXISTS mta_sts_mode ENUM('none', 'testing', 'enforce') NOT NULL DEFAULT 'testing';
