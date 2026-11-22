-- 0013: mail-service views for app passwords, two-factor login, shared mailboxes and the
-- company directory (spec 17.1, 17.5, 17.8).
--
-- Same rules as 0005: "active" means the mailbox's status is 'active' AND its domain's status is
-- 'active'; nothing is cached, so every change takes effect on the next lookup; every text
-- column is ascii_bin except in v_directory (see there). v_auth and v_sender_login are
-- redefined here and replace the 0005 versions; v_mailboxes, v_aliases and v_rejected_* are
-- unchanged and already cover shared mailboxes like any other mailbox.
--
-- Re-running every migration (schema_migrations cleared) recreates the 0005 versions first, so
-- until this file runs again v_auth briefly lists 2FA and shared mailboxes. Stop Postfix,
-- Dovecot and the portal before a full re-run; a normal migrate only applies new files.
--
-- A shared mailbox (kind 'shared') never logs in: it is left out of v_auth, v_app_auth and the
-- send-as-itself branch of v_sender_login. Its members reach it through shared_access, and
-- only when the shared mailbox and the member are both active, in the same domain, and of
-- the right kinds (shared, personal). shared_access itself does not enforce those rules.

-- Dovecot passdb for the main password: active personal mailboxes without 2FA. Once 2FA is on
-- (require_app_passwords = 1), the main password stops working for IMAP, SMTP and CardDAV,
-- so a stolen main password cannot read mail; only app passwords (v_app_auth) still do.
CREATE OR REPLACE VIEW v_auth AS
SELECT
    CONCAT(m.local_part, '@', d.name) AS email,
    CASE
        WHEN m.password_hash LIKE '$argon2id$%' THEN CONCAT('{ARGON2ID}', m.password_hash)
        ELSE CONCAT('{BLF-CRYPT}', m.password_hash)
    END AS password
FROM mailboxes m
JOIN domains d ON d.id = m.domain_id
WHERE m.status = 'active' AND d.status = 'active'
  AND m.kind = 'personal' AND m.require_app_passwords = 0;

-- Dovecot passdb for app passwords: one row per live (not revoked) app password of an active
-- personal mailbox, so a user can have several rows. Dovecot checks this view first, then
-- v_auth. How Dovecot tries several rows for one user (an SQL passdb returning one row per
-- password, or a Lua passdb that loops over them) is decided in step 2; app_password_id lets
-- the login be recorded against the password used (login_events, last_used_at).
CREATE OR REPLACE VIEW v_app_auth AS
SELECT
    CONCAT(m.local_part, '@', d.name) AS email,
    CONCAT('{ARGON2ID}', p.password_hash) AS password,
    p.id AS app_password_id
FROM app_passwords p
JOIN mailboxes m ON m.id = p.mailbox_id
JOIN domains d ON d.id = m.domain_id
WHERE p.revoked_at IS NULL
  AND m.status = 'active' AND d.status = 'active'
  AND m.kind = 'personal';

-- Postfix smtpd_sender_login_maps, as in 0005 with two changes:
--   * only a personal mailbox may send as itself (a shared address has no login);
--   * a shared address may be used by each member with can_send = 1, when the shared mailbox
--     and the member are both active, in the same domain, and shared and personal respectively.
CREATE OR REPLACE VIEW v_sender_login AS
SELECT
    CONCAT(m.local_part, '@', d.name) AS sender,
    CONCAT(m.local_part, '@', d.name) AS login
FROM mailboxes m
JOIN domains d ON d.id = m.domain_id
WHERE m.status = 'active' AND d.status = 'active'
  AND m.kind = 'personal'
UNION
SELECT
    CONCAT(a.local_part, '@', ad.name),
    t.destination
FROM aliases a
JOIN domains ad ON ad.id = a.domain_id
JOIN alias_targets t ON t.alias_id = a.id
JOIN domains md ON md.name = SUBSTRING_INDEX(t.destination, '@', -1)
JOIN mailboxes m ON m.domain_id = md.id AND CONCAT(m.local_part, '@', md.name) = t.destination
WHERE a.active = 1 AND ad.status = 'active'
  AND m.status = 'active' AND md.status = 'active'
UNION
SELECT
    CONCAT(s.local_part, '@', d.name),
    CONCAT(mm.local_part, '@', d.name)
FROM shared_access sa
JOIN mailboxes s ON s.id = sa.shared_mailbox_id
JOIN mailboxes mm ON mm.id = sa.member_mailbox_id AND mm.domain_id = s.domain_id
JOIN domains d ON d.id = s.domain_id
WHERE sa.can_send = 1
  AND s.kind = 'shared' AND mm.kind = 'personal'
  AND s.status = 'active' AND mm.status = 'active' AND d.status = 'active';

-- IMAP rights of each member on each shared mailbox, for Dovecot's shared namespace and ACL
-- plugin (or the dovecot-acl files mailctl-deploy writes, if Dovecot cannot read ACLs from
-- SQL, spec 17.14). One row per member with can_read = 1, under the same rules as the shared
-- branch of v_sender_login. rights is the same for everyone: lookup, read, seen, write flags,
-- delete flag, insert and expunge (no create, delete mailbox or ACL admin).
CREATE OR REPLACE VIEW v_shared_acl AS
SELECT
    CONCAT(s.local_part, '@', d.name) AS shared_email,
    CONCAT(d.name, '/', s.local_part, '/') AS shared_maildir,
    CONCAT(mm.local_part, '@', d.name) AS member_login,
    CONVERT('lrwstie' USING ascii) COLLATE ascii_bin AS rights
FROM shared_access sa
JOIN mailboxes s ON s.id = sa.shared_mailbox_id
JOIN mailboxes mm ON mm.id = sa.member_mailbox_id AND mm.domain_id = s.domain_id
JOIN domains d ON d.id = s.domain_id
WHERE sa.can_read = 1
  AND s.kind = 'shared' AND mm.kind = 'personal'
  AND s.status = 'active' AND mm.status = 'active' AND d.status = 'active';

-- The company address book (read-only CardDAV): active mailboxes of active domains, personal
-- and shared, unless hidden with directory_visible = 0. display_name falls back to the local
-- part. The profile columns are utf8mb4 free text (0007), so this view is not ascii_bin; it is
-- read by the portal's CardDAV backend only, never by Postfix or Dovecot. The backend shows a
-- user only the rows of their own domain.
CREATE OR REPLACE VIEW v_directory AS
SELECT
    d.name AS domain,
    CONCAT(m.local_part, '@', d.name) AS email,
    COALESCE(m.display_name, CONVERT(m.local_part USING utf8mb4) COLLATE utf8mb4_unicode_ci) AS display_name,
    m.job_title AS job_title,
    m.department AS department,
    m.phone AS phone,
    m.kind AS kind
FROM mailboxes m
JOIN domains d ON d.id = m.domain_id
WHERE m.status = 'active' AND d.status = 'active'
  AND m.directory_visible = 1;
