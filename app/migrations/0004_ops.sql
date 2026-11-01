-- 0004: spam filter policy, quarantine, one-time codes, sessions, audit log, jobs and settings.

-- Single-row table holding the global filter policy; the bounds limit what a domain may set.
CREATE TABLE IF NOT EXISTS filter_global (
    id TINYINT UNSIGNED NOT NULL DEFAULT 1,
    tag_score DECIMAL(5,2) NOT NULL,
    quarantine_score DECIMAL(5,2) NOT NULL,
    reject_score DECIMAL(5,2) NOT NULL,
    virus_action ENUM('reject', 'quarantine') NOT NULL DEFAULT 'reject',
    unscannable_action ENUM('quarantine', 'tag', 'reject') NOT NULL DEFAULT 'quarantine',
    bound_min_score DECIMAL(5,2) NOT NULL,
    bound_max_score DECIMAL(5,2) NOT NULL,
    PRIMARY KEY (id),
    CONSTRAINT chk_filter_global_single_row CHECK (id = 1),
    CONSTRAINT chk_filter_global_scores_ordered CHECK (tag_score <= quarantine_score AND quarantine_score <= reject_score),
    CONSTRAINT chk_filter_global_bounds_ordered CHECK (bound_min_score <= bound_max_score)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Per-domain overrides. The app enforces the global bounds when it saves a row.
CREATE TABLE IF NOT EXISTS filter_policies (
    domain_id INT UNSIGNED NOT NULL,
    tag_score DECIMAL(5,2) NOT NULL,
    quarantine_score DECIMAL(5,2) NOT NULL,
    reject_score DECIMAL(5,2) NOT NULL,
    virus_action ENUM('reject', 'quarantine') NOT NULL DEFAULT 'reject',
    unscannable_action ENUM('quarantine', 'tag', 'reject') NOT NULL DEFAULT 'quarantine',
    PRIMARY KEY (domain_id),
    CONSTRAINT fk_filter_policies_domain FOREIGN KEY (domain_id) REFERENCES domains (id) ON DELETE CASCADE,
    CONSTRAINT chk_filter_policies_scores_ordered CHECK (tag_score <= quarantine_score AND quarantine_score <= reject_score)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS quarantine_items (
    id INT UNSIGNED NOT NULL AUTO_INCREMENT,
    queue_id VARCHAR(32) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    domain_id INT UNSIGNED NULL,
    envelope_from VARCHAR(254) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    envelope_to TEXT NOT NULL,
    score DECIMAL(6,2) NOT NULL,
    reason VARCHAR(1024) NOT NULL,
    size_bytes INT UNSIGNED NOT NULL,
    held_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    status ENUM('held', 'released', 'deleted') NOT NULL DEFAULT 'held',
    PRIMARY KEY (id),
    UNIQUE KEY uq_quarantine_items_queue_id (queue_id),
    KEY ix_quarantine_items_domain (domain_id),
    CONSTRAINT fk_quarantine_items_domain FOREIGN KEY (domain_id) REFERENCES domains (id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- target is the new address for a verify_email code.
CREATE TABLE IF NOT EXISTS otp_codes (
    id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    subject_type ENUM('mailbox', 'admin') NOT NULL,
    subject_id INT UNSIGNED NOT NULL,
    purpose ENUM('login', 'recovery', 'verify_email') NOT NULL,
    code_hmac CHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    target VARCHAR(254) CHARACTER SET ascii COLLATE ascii_bin NULL,
    expires_at DATETIME NOT NULL,
    attempts TINYINT UNSIGNED NOT NULL DEFAULT 0,
    used_at DATETIME NULL,
    request_ip VARCHAR(45) NOT NULL,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (id),
    KEY ix_otp_codes_subject_purpose (subject_type, subject_id, purpose),
    CONSTRAINT chk_otp_codes_code_hmac_lc CHECK (code_hmac = LOWER(code_hmac)),
    CONSTRAINT chk_otp_codes_target_lc CHECK (target = LOWER(target))
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS sessions (
    token_hash CHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    subject_type ENUM('admin', 'mailbox') NOT NULL,
    subject_id INT UNSIGNED NOT NULL,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    last_seen_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    expires_at DATETIME NOT NULL,
    ip VARCHAR(45) NOT NULL,
    user_agent VARCHAR(255) NOT NULL,
    revoked_at DATETIME NULL,
    PRIMARY KEY (token_hash),
    KEY ix_sessions_subject (subject_type, subject_id),
    CONSTRAINT chk_sessions_token_hash_lc CHECK (token_hash = LOWER(token_hash))
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- domain_id has no foreign key on purpose, so the history survives deleting a domain.
CREATE TABLE IF NOT EXISTS audit_log (
    id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    at DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
    actor_type ENUM('admin', 'mailbox', 'system', 'anonymous') NOT NULL,
    actor_id INT UNSIGNED NULL,
    action VARCHAR(64) NOT NULL,
    target_type VARCHAR(32) NULL,
    target_id VARCHAR(255) NULL,
    domain_id INT UNSIGNED NULL,
    ip VARCHAR(45) NULL,
    details JSON NULL,
    PRIMARY KEY (id),
    KEY ix_audit_log_at (at),
    KEY ix_audit_log_domain_at (domain_id, at),
    KEY ix_audit_log_actor (actor_type, actor_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS deployments (
    id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    job_type ENUM(
        'dkim_generate',
        'rspamd_policy',
        'doveadm_kick',
        'quarantine_release',
        'quarantine_delete',
        'domain_archive',
        'mailbox_archive',
        'retention_sweep'
    ) NOT NULL,
    payload JSON NOT NULL,
    status ENUM('queued', 'running', 'applied', 'failed', 'rolled_back') NOT NULL DEFAULT 'queued',
    requested_by_type ENUM('admin', 'mailbox', 'system') NOT NULL,
    requested_by_id INT UNSIGNED NULL,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    finished_at DATETIME NULL,
    log MEDIUMTEXT NULL,
    PRIMARY KEY (id),
    KEY ix_deployments_status_id (status, id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS settings (
    `key` VARCHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    value VARCHAR(255) NOT NULL,
    PRIMARY KEY (`key`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

INSERT IGNORE INTO filter_global
    (id, tag_score, quarantine_score, reject_score, virus_action, unscannable_action, bound_min_score, bound_max_score)
VALUES
    (1, 6.00, 10.00, 15.00, 'reject', 'quarantine', 4.00, 25.00);

INSERT IGNORE INTO settings (`key`, value) VALUES
    ('otp_ttl_minutes', '10'),
    ('otp_max_attempts', '5'),
    ('external_forwarding', 'allow'),
    ('superadmin_list_override', 'allow'),
    ('retention_suspended_days', '30'),
    ('retention_archive_days', '90'),
    ('max_message_mb', '25');
