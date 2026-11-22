-- 0014: the portal's views for per-mailbox jobs, authenticator secrets, recovery codes and
-- login events (spec 17.4, 17.5, 17.6, 17.7).
--
-- As in 0006, each WHERE clause is the set of rows the internet-facing portal may ever hold,
-- and WITH CASCADED CHECK OPTION makes MariaDB refuse (error 1369) any INSERT or UPDATE that
-- would leave it. The portal never gets a grant on totp_secrets, recovery_codes or
-- login_events themselves (Grants::mailPortal), so it can never read, create or change an
-- admin's 2FA secret, recovery code or login history.
--
-- Re-running every migration recreates the 0006 version of v_portal_deployments first; stop
-- the portal before a full re-run (see 0013).

-- Redefines the 0006 view. The portal may queue three jobs, each for one mailbox: doveadm_kick
-- (sign out everywhere, a revoked app password), sieve_compile (rules and out-of-office) and
-- spam_lists (allow/block lists). The payload must be exactly {"mailbox_id": <requester>}:
-- compared after JSON_COMPACT, so spacing does not matter, but a string or fractional id, an
-- extra key or a second "mailbox_id" key is refused. The last case matters: JSON_VALUE reads
-- the first of two equal keys while PHP's json_decode keeps the last, so a looser check
-- (CAST(JSON_VALUE(payload, '$.mailbox_id') AS UNSIGNED) = requested_by_id) would let a
-- payload name one mailbox to the view and another to the job runner.
CREATE OR REPLACE VIEW v_portal_deployments AS
SELECT
    d.id AS id,
    d.job_type AS job_type,
    d.payload AS payload,
    d.requested_by_type AS requested_by_type,
    d.requested_by_id AS requested_by_id
FROM deployments d
WHERE d.job_type IN ('doveadm_kick', 'sieve_compile', 'spam_lists')
  AND d.requested_by_type = 'mailbox'
  AND d.requested_by_id IS NOT NULL
  AND JSON_COMPACT(d.payload) = JSON_COMPACT(JSON_OBJECT('mailbox_id', d.requested_by_id))
WITH CASCADED CHECK OPTION;

-- Mailbox authenticator secrets only.
CREATE OR REPLACE VIEW v_portal_totp_secrets AS
SELECT
    t.subject_type AS subject_type,
    t.subject_id AS subject_id,
    t.secret_enc AS secret_enc,
    t.confirmed_at AS confirmed_at,
    t.last_used_step AS last_used_step,
    t.created_at AS created_at
FROM totp_secrets t
WHERE t.subject_type = 'mailbox'
WITH CASCADED CHECK OPTION;

-- Mailbox recovery codes only.
CREATE OR REPLACE VIEW v_portal_recovery_codes AS
SELECT
    r.id AS id,
    r.subject_type AS subject_type,
    r.subject_id AS subject_id,
    r.code_hash AS code_hash,
    r.used_at AS used_at,
    r.created_at AS created_at
FROM recovery_codes r
WHERE r.subject_type = 'mailbox'
WITH CASCADED CHECK OPTION;

-- The login events the portal writes itself: portal and CardDAV logins of mailboxes, and of
-- logins that name no account ('unknown'). It cannot write or see admin logins, nor the IMAP
-- and SMTP events that mailhost-status reads from the logs.
CREATE OR REPLACE VIEW v_portal_login_events AS
SELECT
    e.id AS id,
    e.at AS at,
    e.subject_type AS subject_type,
    e.subject_id AS subject_id,
    e.login AS login,
    e.service AS service,
    e.result AS result,
    e.ip AS ip,
    e.country AS country,
    e.client AS client,
    e.app_password_id AS app_password_id
FROM login_events e
WHERE e.subject_type IN ('mailbox', 'unknown') AND e.service IN ('portal', 'dav')
WITH CASCADED CHECK OPTION;

-- Release requests the portal may still change: an offer from the digest, or a request the
-- user has made. The portal turns 'offered' into 'requested' (with requested_at); approving,
-- rejecting and expiring belong to admins and mailctl, so any other status leaves the view and
-- is refused, and a decided request cannot be reopened. Release stays admin-only (spec 17.7).
CREATE OR REPLACE VIEW v_portal_release_requests AS
SELECT
    r.id AS id,
    r.quarantine_item_id AS quarantine_item_id,
    r.mailbox_id AS mailbox_id,
    r.token_hash AS token_hash,
    r.status AS status,
    r.requested_at AS requested_at,
    r.decided_at AS decided_at,
    r.decided_by AS decided_by,
    r.expires_at AS expires_at
FROM release_requests r
WHERE r.status IN ('offered', 'requested')
WITH CASCADED CHECK OPTION;

-- "Recent activity" in the portal (spec 17.6): every login event tied to a mailbox, for every
-- service (IMAP, SMTP, portal, CardDAV), successful or not. Events that name no account and
-- admin logins stay out. The portal only reads this view (SELECT grant, no CHECK OPTION
-- needed) and shows a user the rows of their own mailbox.
CREATE OR REPLACE VIEW v_portal_activity AS
SELECT
    e.id AS id,
    e.at AS at,
    e.subject_id AS subject_id,
    e.login AS login,
    e.service AS service,
    e.result AS result,
    e.ip AS ip,
    e.country AS country,
    e.client AS client,
    e.app_password_id AS app_password_id
FROM login_events e
WHERE e.subject_type = 'mailbox';
