-- 0006: the views behind the list-sender policy service and the portal job queue.
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
WHERE l.status = 'active' AND d.status = 'active';

-- Who may post to each list in v_lists. value is empty for any_authenticated.
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

-- The only way the public portal may queue a job. The view shows just the columns the
-- portal may set (status, created_at, finished_at and log keep their defaults, so every
-- job starts 'queued'), and WITH CASCADED CHECK OPTION makes MariaDB refuse, with error
-- 1369, any INSERT or UPDATE of a row that is not a doveadm_kick requested by a mailbox.
CREATE OR REPLACE VIEW v_portal_deployments AS
SELECT
    d.id AS id,
    d.job_type AS job_type,
    d.payload AS payload,
    d.requested_by_type AS requested_by_type,
    d.requested_by_id AS requested_by_id
FROM deployments d
WHERE d.job_type = 'doveadm_kick' AND d.requested_by_type = 'mailbox'
WITH CASCADED CHECK OPTION;
