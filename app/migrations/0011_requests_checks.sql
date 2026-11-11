-- 0011: release and quota requests, domain health results, DMARC reports and IMAP migration
-- jobs (spec 17.7, 17.9, 17.10, 17.11). Every ascii column is ascii_bin.

-- A "request release" link from the quarantine digest. The token is single-use and stored only
-- as a lowercase hex SHA-256 hash. An admin approves or rejects the request, so releasing mail
-- stays admin-only.
CREATE TABLE IF NOT EXISTS release_requests (
    id INT UNSIGNED NOT NULL AUTO_INCREMENT,
    quarantine_item_id INT UNSIGNED NOT NULL,
    mailbox_id INT UNSIGNED NOT NULL,
    token_hash CHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    status ENUM('offered', 'requested', 'approved', 'rejected', 'expired') NOT NULL DEFAULT 'offered',
    requested_at DATETIME NULL,
    decided_at DATETIME NULL,
    decided_by INT UNSIGNED NULL,
    expires_at DATETIME NOT NULL,
    PRIMARY KEY (id),
    UNIQUE KEY uq_release_requests_token_hash (token_hash),
    KEY ix_release_requests_quarantine_item (quarantine_item_id),
    KEY ix_release_requests_mailbox (mailbox_id),
    KEY ix_release_requests_decided_by (decided_by),
    CONSTRAINT fk_release_requests_quarantine_item FOREIGN KEY (quarantine_item_id) REFERENCES quarantine_items (id) ON DELETE CASCADE,
    CONSTRAINT fk_release_requests_mailbox FOREIGN KEY (mailbox_id) REFERENCES mailboxes (id) ON DELETE CASCADE,
    CONSTRAINT fk_release_requests_decided_by FOREIGN KEY (decided_by) REFERENCES admins (id) ON DELETE SET NULL,
    CONSTRAINT chk_release_requests_token_hash_lc CHECK (token_hash = LOWER(token_hash))
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- "Request more space" from the portal. When an admin approves, the app sets the new quota.
CREATE TABLE IF NOT EXISTS quota_requests (
    id INT UNSIGNED NOT NULL AUTO_INCREMENT,
    mailbox_id INT UNSIGNED NOT NULL,
    requested_mb INT UNSIGNED NOT NULL,
    note VARCHAR(500) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci NULL,
    status ENUM('pending', 'approved', 'rejected') NOT NULL DEFAULT 'pending',
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    decided_at DATETIME NULL,
    decided_by INT UNSIGNED NULL,
    PRIMARY KEY (id),
    KEY ix_quota_requests_mailbox (mailbox_id),
    KEY ix_quota_requests_decided_by (decided_by),
    CONSTRAINT fk_quota_requests_mailbox FOREIGN KEY (mailbox_id) REFERENCES mailboxes (id) ON DELETE CASCADE,
    CONSTRAINT fk_quota_requests_decided_by FOREIGN KEY (decided_by) REFERENCES admins (id) ON DELETE SET NULL,
    CONSTRAINT chk_quota_requests_requested_mb_positive CHECK (requested_mb > 0)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- The latest result of each health check of each domain, written by mailhost-status.
CREATE TABLE IF NOT EXISTS domain_checks (
    domain_id INT UNSIGNED NOT NULL,
    check_name ENUM('mx', 'spf', 'dkim', 'dmarc', 'autoconfig', 'autodiscover', 'mta_sts', 'tls_rpt', 'ptr') NOT NULL,
    status ENUM('ok', 'warn', 'fail') NOT NULL,
    detail VARCHAR(500) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci NOT NULL,
    checked_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (domain_id, check_name),
    CONSTRAINT fk_domain_checks_domain FOREIGN KEY (domain_id) REFERENCES domains (id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- DMARC aggregate reports received at dmarc-reports@PRIMARY_DOMAIN, one row per report.
-- A reporter's report id is unique, so the same report delivered twice is stored once.
-- domain_id is the hosted domain the report is about; it has no foreign key, so the
-- history outlives the domain until the retention setting removes it.
CREATE TABLE IF NOT EXISTS dmarc_reports (
    id INT UNSIGNED NOT NULL AUTO_INCREMENT,
    org_name VARCHAR(255) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci NOT NULL,
    report_id VARCHAR(255) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci NOT NULL,
    policy_domain VARCHAR(253) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    domain_id INT UNSIGNED NULL,
    date_begin DATETIME NOT NULL,
    date_end DATETIME NOT NULL,
    policy_p ENUM('none', 'quarantine', 'reject') NULL,
    received_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (id),
    UNIQUE KEY uq_dmarc_reports_org_report (org_name, report_id),
    KEY ix_dmarc_reports_domain_begin (domain_id, date_begin),
    CONSTRAINT chk_dmarc_reports_policy_domain_lc CHECK (policy_domain = LOWER(policy_domain))
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- The rows of each report: one per source IP and result combination, with its message count.
CREATE TABLE IF NOT EXISTS dmarc_records (
    id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    report_id INT UNSIGNED NOT NULL,
    source_ip VARCHAR(45) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    `count` INT UNSIGNED NOT NULL,
    disposition ENUM('none', 'quarantine', 'reject') NOT NULL,
    dkim_result VARCHAR(16) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    spf_result VARCHAR(16) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    header_from VARCHAR(253) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    PRIMARY KEY (id),
    KEY ix_dmarc_records_report (report_id),
    CONSTRAINT fk_dmarc_records_report FOREIGN KEY (report_id) REFERENCES dmarc_reports (id) ON DELETE CASCADE,
    CONSTRAINT chk_dmarc_records_header_from_lc CHECK (header_from = LOWER(header_from))
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Copying a mailbox from an old provider with imapsync (job imap_migrate). host is a domain in
-- the 0001 format or an IPv4 address. TLS is required: there is no plaintext mode. The old
-- password is ciphertext (the app encrypts it with a server key) and must be gone once the job
-- has ended; expires_at (7 days at most) lets the retention sweep clear a job that never ran.
CREATE TABLE IF NOT EXISTS migration_jobs (
    id INT UNSIGNED NOT NULL AUTO_INCREMENT,
    mailbox_id INT UNSIGNED NOT NULL,
    host VARCHAR(253) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    port SMALLINT UNSIGNED NOT NULL,
    tls ENUM('ssl', 'starttls') NOT NULL,
    username VARCHAR(254) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci NOT NULL,
    password_enc VARBINARY(512) NULL,
    status ENUM('queued', 'running', 'done', 'failed', 'cancelled') NOT NULL DEFAULT 'queued',
    messages_total INT UNSIGNED NULL,
    messages_copied INT UNSIGNED NULL,
    error VARCHAR(500) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci NULL,
    created_by INT UNSIGNED NULL,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    started_at DATETIME NULL,
    finished_at DATETIME NULL,
    expires_at DATETIME NOT NULL,
    PRIMARY KEY (id),
    KEY ix_migration_jobs_mailbox (mailbox_id),
    KEY ix_migration_jobs_created_by (created_by),
    CONSTRAINT fk_migration_jobs_mailbox FOREIGN KEY (mailbox_id) REFERENCES mailboxes (id) ON DELETE CASCADE,
    CONSTRAINT fk_migration_jobs_created_by FOREIGN KEY (created_by) REFERENCES admins (id) ON DELETE SET NULL,
    CONSTRAINT chk_migration_jobs_host_lc CHECK (host = LOWER(host)),
    CONSTRAINT chk_migration_jobs_host_format CHECK (
        host REGEXP '^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+\\z'
        OR host REGEXP '^([0-9]{1,3}\\.){3}[0-9]{1,3}\\z'
    ),
    CONSTRAINT chk_migration_jobs_port_range CHECK (port BETWEEN 1 AND 65535),
    CONSTRAINT chk_migration_jobs_username_text CHECK (username <> '' AND username NOT REGEXP '[[:cntrl:]]'),
    CONSTRAINT chk_migration_jobs_password_cleared CHECK (status IN ('queued', 'running') OR password_enc IS NULL)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
