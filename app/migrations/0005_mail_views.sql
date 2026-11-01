-- 0005: the views Postfix and Dovecot read, through a SELECT-only database user.
--
-- Rules shared by every view:
--   * "Active" means the row's status is 'active' AND its domain's status is 'active'
--     ('suspended' and 'deleting' both count as not active). Aliases and forwarding
--     rules must also have active = 1. Nothing is cached, so a status change takes
--     effect on the very next lookup, with no reload.
--   * Addresses are built as local_part + '@' + domain name. A catch-all alias has an
--     empty local part, so its source comes out as '@domain'.
--   * Safe to re-run: CREATE OR REPLACE VIEW. Views are listed in dependency order,
--     so v_local_addresses comes before v_aliases, which reads it.
--   * v_local_addresses is an internal helper and is never granted to a service user.

-- Every address that exists as a local recipient: active mailboxes, active
-- non-catch-all aliases and active lists. UNION removes duplicates.
CREATE OR REPLACE VIEW v_local_addresses AS
SELECT m.domain_id AS domain_id, m.local_part AS local_part
FROM mailboxes m
JOIN domains d ON d.id = m.domain_id
WHERE m.status = 'active' AND d.status = 'active'
UNION
SELECT a.domain_id, a.local_part
FROM aliases a
JOIN domains d ON d.id = a.domain_id
WHERE a.active = 1 AND a.local_part <> '' AND d.status = 'active'
UNION
SELECT l.domain_id, l.local_part
FROM lists l
JOIN domains d ON d.id = l.domain_id
WHERE l.status = 'active' AND d.status = 'active';

-- Domains Postfix accepts mail for: active domains plus the alias domains of active domains.
CREATE OR REPLACE VIEW v_domains AS
SELECT d.name AS name
FROM domains d
WHERE d.status = 'active'
UNION
SELECT da.alias_domain
FROM domain_aliases da
JOIN domains d ON d.id = da.target_domain_id
WHERE d.status = 'active';

CREATE OR REPLACE VIEW v_mailboxes AS
SELECT
    CONCAT(m.local_part, '@', d.name) AS email,
    CONCAT(d.name, '/', m.local_part, '/') AS maildir,
    m.quota_mb AS quota_mb
FROM mailboxes m
JOIN domains d ON d.id = m.domain_id
WHERE m.status = 'active' AND d.status = 'active';

-- Dovecot passdb: the stored hash with its scheme in front. 0001 allows only
-- $argon2id$ and $2y$ hashes, so anything that is not Argon2id is bcrypt.
CREATE OR REPLACE VIEW v_auth AS
SELECT
    CONCAT(m.local_part, '@', d.name) AS email,
    CASE
        WHEN m.password_hash LIKE '$argon2id$%' THEN CONCAT('{ARGON2ID}', m.password_hash)
        ELSE CONCAT('{BLF-CRYPT}', m.password_hash)
    END AS password
FROM mailboxes m
JOIN domains d ON d.id = m.domain_id
WHERE m.status = 'active' AND d.status = 'active';

-- Postfix virtual alias map: one row per (source, destination). Five parts, in order:
--   a. alias targets (the catch-all gives source '@domain');
--   b. the active forwarding rules of an active mailbox;
--   c. the identity row, mailbox to itself. It must exist whenever the mailbox keeps
--      receiving its own mail, because Postfix tries the full address before the
--      catch-all: without it a catch-all would swallow the mailbox's mail. It is
--      left out only when the mailbox has active rules and none of them keeps a copy;
--   d. list to member, for an active list and an active member row whose mailbox is
--      active (so the member's own domain is active too);
--   e. alias domains: lp@alias_domain to lp@target for every local address of an
--      active target domain, so unknown addresses at an alias domain are still rejected.
CREATE OR REPLACE VIEW v_aliases AS
SELECT
    CONCAT(a.local_part, '@', d.name) AS source,
    t.destination AS destination
FROM aliases a
JOIN domains d ON d.id = a.domain_id
JOIN alias_targets t ON t.alias_id = a.id
WHERE a.active = 1 AND d.status = 'active'
UNION ALL
SELECT
    CONCAT(m.local_part, '@', d.name),
    f.destination
FROM forwarding_rules f
JOIN mailboxes m ON m.id = f.mailbox_id
JOIN domains d ON d.id = m.domain_id
WHERE f.active = 1 AND m.status = 'active' AND d.status = 'active'
UNION ALL
SELECT
    CONCAT(m.local_part, '@', d.name),
    CONCAT(m.local_part, '@', d.name)
FROM mailboxes m
JOIN domains d ON d.id = m.domain_id
WHERE m.status = 'active' AND d.status = 'active'
  AND (
      NOT EXISTS (
          SELECT 1 FROM forwarding_rules f
          WHERE f.mailbox_id = m.id AND f.active = 1
      )
      OR EXISTS (
          SELECT 1 FROM forwarding_rules f
          WHERE f.mailbox_id = m.id AND f.active = 1 AND f.keep_copy = 1
      )
  )
UNION ALL
SELECT
    CONCAT(l.local_part, '@', ld.name),
    CONCAT(m.local_part, '@', md.name)
FROM lists l
JOIN domains ld ON ld.id = l.domain_id
JOIN list_members lm ON lm.list_id = l.id
JOIN mailboxes m ON m.id = lm.mailbox_id
JOIN domains md ON md.id = m.domain_id
WHERE l.status = 'active' AND ld.status = 'active'
  AND lm.status = 'active'
  AND m.status = 'active' AND md.status = 'active'
UNION ALL
SELECT
    CONCAT(la.local_part, '@', da.alias_domain),
    CONCAT(la.local_part, '@', td.name)
FROM domain_aliases da
JOIN domains td ON td.id = da.target_domain_id
JOIN v_local_addresses la ON la.domain_id = td.id
WHERE td.status = 'active';

-- Postfix smtpd_sender_login_maps: sender address to the logins allowed to use it.
-- An active mailbox may send as itself. An active non-catch-all alias address may be
-- used by each of its targets that is an active local mailbox.
CREATE OR REPLACE VIEW v_sender_login AS
SELECT
    CONCAT(m.local_part, '@', d.name) AS sender,
    CONCAT(m.local_part, '@', d.name) AS login
FROM mailboxes m
JOIN domains d ON d.id = m.domain_id
WHERE m.status = 'active' AND d.status = 'active'
UNION
SELECT
    CONCAT(a.local_part, '@', ad.name),
    t.destination
FROM aliases a
JOIN domains ad ON ad.id = a.domain_id
JOIN alias_targets t ON t.alias_id = a.id
JOIN domains md ON md.name = SUBSTRING_INDEX(t.destination, '@', -1)
JOIN mailboxes m ON m.domain_id = md.id AND CONCAT(m.local_part, '@', md.name) = t.destination
WHERE a.active = 1 AND a.local_part <> '' AND ad.status = 'active'
  AND m.status = 'active' AND md.status = 'active';
