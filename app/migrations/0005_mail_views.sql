-- 0005: the views Postfix and Dovecot read, through a SELECT-only database user.
--
-- Rules shared by every view:
--   * "Active" means the row's status is 'active' AND its domain's status is 'active'
--     ('suspended' and 'deleting' both count as not active). Aliases and forwarding
--     rules must also have active = 1. Nothing is cached, so a status change takes
--     effect on the very next lookup, with no reload.
--   * Addresses are built as local_part + '@' + domain name. Local parts are never empty
--     (0001 forbids catch-all aliases), so every address names one real recipient.
--   * A real domain always beats an alias domain of the same name, whatever the real
--     domain's status: every branch that reads domain_aliases carries
--     NOT EXISTS (SELECT 1 FROM domains x WHERE x.name = da.alias_domain). Otherwise listing
--     b.com as an alias of example.com while b.com is also hosted would copy or reject
--     b.com's mail on behalf of example.com's users.
--   * Every text column is ascii_bin, like the identifier columns of the base tables.
--   * Safe to re-run: CREATE OR REPLACE VIEW. Views are listed in dependency order,
--     so v_local_addresses comes before v_aliases, which reads it.
--   * v_local_addresses and v_rejected_local are internal helpers and are never granted
--     to a service user.

-- Every address that exists as a local recipient: active mailboxes, active aliases
-- and active lists. UNION removes duplicates.
CREATE OR REPLACE VIEW v_local_addresses AS
SELECT m.domain_id AS domain_id, m.local_part AS local_part
FROM mailboxes m
JOIN domains d ON d.id = m.domain_id
WHERE m.status = 'active' AND d.status = 'active'
UNION
SELECT a.domain_id, a.local_part
FROM aliases a
JOIN domains d ON d.id = a.domain_id
WHERE a.active = 1 AND d.status = 'active'
UNION
SELECT l.domain_id, l.local_part
FROM lists l
JOIN domains d ON d.id = l.domain_id
WHERE l.status = 'active' AND d.status = 'active';

-- Domains Postfix accepts mail for: active domains plus the alias domains of active domains
-- (an alias domain that is also a real domain is that real domain, see above).
CREATE OR REPLACE VIEW v_domains AS
SELECT d.name AS name
FROM domains d
WHERE d.status = 'active'
UNION
SELECT da.alias_domain
FROM domain_aliases da
JOIN domains d ON d.id = da.target_domain_id
WHERE d.status = 'active'
  AND NOT EXISTS (SELECT 1 FROM domains x WHERE x.name = da.alias_domain);

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
--   a. alias targets;
--   b. the active forwarding rules of an active mailbox;
--   c. the identity row, mailbox to itself. Postfix replaces an address with the rows it
--      finds for it, so a forwarded mailbox keeps receiving its own copy only if it also
--      maps to itself. The row is there when the mailbox has no active rules, or when any
--      active rule has keep_copy = 1, and left out only when every active rule is
--      forward-only (keep_copy = 0);
--   d. list to member, for an active list and an active member row whose mailbox is
--      active (so the member's own domain is active too);
--   e. alias domains: lp@alias_domain to lp@target for every local address of an
--      active target domain, so unknown addresses at an alias domain are still rejected.
--      Not for an alias domain that is also a real domain.
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
WHERE td.status = 'active'
  AND NOT EXISTS (SELECT 1 FROM domains x WHERE x.name = da.alias_domain);

-- Postfix smtpd_sender_login_maps: sender address to the logins allowed to use it.
-- An active mailbox may send as itself. An active alias address may be used by each of
-- its targets that is an active local mailbox.
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
WHERE a.active = 1 AND ad.status = 'active'
  AND m.status = 'active' AND md.status = 'active';

-- Addresses that exist in the database but must not receive mail, in active domains only.
-- A non-active mailbox, list or alias has no v_aliases row. Step 2 wires
-- v_rejected_recipients as Postfix check_recipient_access, so mail sent directly to such
-- an address gets a clean rejection at SMTP time. This does not cover an address that is
-- only a target of an active alias (for example an alias to a suspended mailbox): that
-- mail is accepted and then bounces, because the target is not in v_mailboxes.
--
-- v_rejected_local has one row per (domain_id, local_part) with the reason:
--   mailbox_inactive  a mailbox that is suspended or deleting;
--   list_inactive     a list that is suspended;
--   list_empty        an active list with no deliverable member (the same member test as
--                     part d of v_aliases: active member row, active mailbox, active domain);
--   alias_inactive    an alias with active = 0;
--   alias_empty       an active alias with no alias_targets row.
-- If one local part falls under several reasons, the alphabetically first reason wins
-- (MIN), so there is one row each. The reason column is ascii_bin.
CREATE OR REPLACE VIEW v_rejected_local AS
SELECT
    r.domain_id AS domain_id,
    r.local_part AS local_part,
    MIN(CONVERT(r.reason USING ascii) COLLATE ascii_bin) AS reason
FROM (
    SELECT m.domain_id AS domain_id, m.local_part AS local_part, 'mailbox_inactive' AS reason
    FROM mailboxes m
    JOIN domains d ON d.id = m.domain_id
    WHERE m.status <> 'active' AND d.status = 'active'
    UNION ALL
    SELECT
        l.domain_id,
        l.local_part,
        CASE WHEN l.status <> 'active' THEN 'list_inactive' ELSE 'list_empty' END
    FROM lists l
    JOIN domains d ON d.id = l.domain_id
    WHERE d.status = 'active'
      AND (
          l.status <> 'active'
          OR NOT EXISTS (
              SELECT 1
              FROM list_members lm
              JOIN mailboxes m ON m.id = lm.mailbox_id
              JOIN domains md ON md.id = m.domain_id
              WHERE lm.list_id = l.id
                AND lm.status = 'active'
                AND m.status = 'active' AND md.status = 'active'
          )
      )
    UNION ALL
    SELECT
        a.domain_id,
        a.local_part,
        CASE WHEN a.active = 0 THEN 'alias_inactive' ELSE 'alias_empty' END
    FROM aliases a
    JOIN domains d ON d.id = a.domain_id
    WHERE d.status = 'active'
      AND (
          a.active = 0
          OR NOT EXISTS (SELECT 1 FROM alias_targets t WHERE t.alias_id = a.id)
      )
) r
GROUP BY r.domain_id, r.local_part;

-- The rejected addresses as full emails, one row per email: the rows of v_rejected_local,
-- plus lp@alias_domain for each of them whose domain is the target of an alias domain
-- (the target domain must be active, as v_domains requires for the alias domain to work,
-- and the alias domain must not also be a real domain).
CREATE OR REPLACE VIEW v_rejected_recipients AS
SELECT u.email AS email, MIN(u.reason) AS reason
FROM (
    SELECT CONCAT(r.local_part, '@', d.name) AS email, r.reason AS reason
    FROM v_rejected_local r
    JOIN domains d ON d.id = r.domain_id
    WHERE d.status = 'active'
    UNION ALL
    SELECT CONCAT(r.local_part, '@', da.alias_domain), r.reason
    FROM domain_aliases da
    JOIN domains td ON td.id = da.target_domain_id
    JOIN v_rejected_local r ON r.domain_id = td.id
    WHERE td.status = 'active'
      AND NOT EXISTS (SELECT 1 FROM domains x WHERE x.name = da.alias_domain)
) u
GROUP BY u.email;
