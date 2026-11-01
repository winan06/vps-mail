-- 0006: the views behind the list-sender policy service and the public portal.
--
-- Rules shared by the read views (v_lists, v_list_sender_rules, v_login_roles):
--   * "Active" means the row's status is 'active' AND its domain's status is 'active'
--     ('suspended' and 'deleting' both count as not active), as in 0005. Nothing is
--     cached, so a status change takes effect on the very next lookup.
--   * Addresses are built as local_part + '@' + domain name, so address, login and
--     value come out ascii_bin like the identifier columns of the base tables.
--     Enum columns (scope, rule_type) keep the table collation.
--   * Safe to re-run: CREATE OR REPLACE VIEW. Views are listed in dependency order,
--     so v_lists comes before v_list_sender_rules, which reads it.

-- Active lists of active domains, with the size limit that applies to each. A list
-- without a limit of its own gets the global max_message_mb setting converted to KB;
-- it is NULL only if that setting row has been deleted.
--
-- Each list appears once per spelling Postfix delivers to it: lp@domain, and lp@alias_domain
-- for every alias domain of its domain (v_aliases in 0005 maps the latter to the former).
-- Without the alias spellings, mail to all@example.net would reach all@example.com's members
-- while the policy service saw "not a list" and skipped the sender rules. As in 0005, an
-- alias domain that is also a real domain is that real domain, and contributes no row.
CREATE OR REPLACE VIEW v_lists AS
SELECT
    CONCAT(l.local_part, '@', d.name) AS address,
    l.id AS list_id,
    l.scope AS scope,
    COALESCE(
        l.max_message_kb,
        (SELECT CAST(s.value AS UNSIGNED) * 1024 FROM settings s WHERE s.`key` = 'max_message_mb')
    ) AS max_message_kb
FROM lists l
JOIN domains d ON d.id = l.domain_id
WHERE l.status = 'active' AND d.status = 'active'
UNION ALL
SELECT
    CONCAT(l.local_part, '@', da.alias_domain),
    l.id,
    l.scope,
    COALESCE(
        l.max_message_kb,
        (SELECT CAST(s.value AS UNSIGNED) * 1024 FROM settings s WHERE s.`key` = 'max_message_mb')
    )
FROM lists l
JOIN domains d ON d.id = l.domain_id
JOIN domain_aliases da ON da.target_domain_id = d.id
WHERE l.status = 'active' AND d.status = 'active'
  AND NOT EXISTS (SELECT 1 FROM domains x WHERE x.name = da.alias_domain);

-- Who may post to each list in v_lists, under every address of the list. value is empty
-- for any_authenticated.
CREATE OR REPLACE VIEW v_list_sender_rules AS
SELECT
    vl.address AS address,
    r.rule_type AS rule_type,
    r.value AS value
FROM list_sender_rules r
JOIN v_lists vl ON vl.list_id = r.list_id;

-- Mailbox logins that belong to an active admin, with the admin's role name. The admin,
-- the linked mailbox and the mailbox's domain must all be active; an admin without a
-- linked mailbox has no row.
CREATE OR REPLACE VIEW v_login_roles AS
SELECT
    CONCAT(m.local_part, '@', d.name) AS login,
    ro.name AS role
FROM admins a
JOIN roles ro ON ro.id = a.role_id
JOIN mailboxes m ON m.id = a.mailbox_id
JOIN domains d ON d.id = m.domain_id
WHERE a.status = 'active' AND m.status = 'active' AND d.status = 'active';

-- The portal views below are the internet-facing portal's only way to their tables. Each
-- WHERE clause is the set of rows the portal may ever hold, and WITH CASCADED CHECK OPTION
-- makes MariaDB refuse, with error 1369, any INSERT or UPDATE that would leave that set. The
-- grants in Grants::mailPortal() then limit which columns the portal may write.

-- The only way the portal may queue a job. The view shows just the columns the portal may
-- set (status, created_at, finished_at and log keep their defaults, so every job starts
-- 'queued'), and its rows are doveadm_kick jobs requested by a named mailbox.
CREATE OR REPLACE VIEW v_portal_deployments AS
SELECT
    d.id AS id,
    d.job_type AS job_type,
    d.payload AS payload,
    d.requested_by_type AS requested_by_type,
    d.requested_by_id AS requested_by_id
FROM deployments d
WHERE d.job_type = 'doveadm_kick' AND d.requested_by_type = 'mailbox' AND d.requested_by_id IS NOT NULL
WITH CASCADED CHECK OPTION;

-- Mailbox sessions only. The portal can neither see an admin session nor create one, so a
-- compromised portal cannot mint an admin login.
CREATE OR REPLACE VIEW v_portal_sessions AS
SELECT
    s.token_hash AS token_hash,
    s.subject_type AS subject_type,
    s.subject_id AS subject_id,
    s.created_at AS created_at,
    s.last_seen_at AS last_seen_at,
    s.expires_at AS expires_at,
    s.ip AS ip,
    s.user_agent AS user_agent,
    s.revoked_at AS revoked_at
FROM sessions s
WHERE s.subject_type = 'mailbox'
WITH CASCADED CHECK OPTION;

-- Mailbox one-time codes only, for the same reason: no admin login or recovery code can be
-- read, created or redeemed through the portal.
CREATE OR REPLACE VIEW v_portal_otp_codes AS
SELECT
    o.id AS id,
    o.subject_type AS subject_type,
    o.subject_id AS subject_id,
    o.purpose AS purpose,
    o.code_hmac AS code_hmac,
    o.target AS target,
    o.expires_at AS expires_at,
    o.attempts AS attempts,
    o.used_at AS used_at,
    o.request_ip AS request_ip,
    o.created_at AS created_at
FROM otp_codes o
WHERE o.subject_type = 'mailbox'
WITH CASCADED CHECK OPTION;
