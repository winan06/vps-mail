-- 0009: login and delivery history, and the journald read positions behind them (spec 17.6, 17.12).
--
-- History tables have no foreign key to domains or mailboxes, so a row outlives what it
-- describes; the retention settings of 0012 decide when rows go. Every ascii column is
-- ascii_bin, so the case-sensitive CHECKs below compare bytes.

-- One row per login attempt. login is what was typed, so it may name no account at all
-- (subject_type 'unknown'). country is the ISO 3166 code from the DB-IP Lite database, in
-- uppercase. Deleting an app password keeps the event and clears the link.
CREATE TABLE IF NOT EXISTS login_events (
    id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    at DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
    subject_type ENUM('mailbox', 'admin', 'unknown') NOT NULL,
    subject_id INT UNSIGNED NULL,
    login VARCHAR(254) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci NOT NULL,
    service ENUM('imap', 'smtp', 'portal', 'admin', 'dav') NOT NULL,
    result ENUM('ok', 'fail') NOT NULL,
    ip VARCHAR(45) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    country CHAR(2) CHARACTER SET ascii COLLATE ascii_bin NULL,
    client VARCHAR(255) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci NULL,
    app_password_id INT UNSIGNED NULL,
    PRIMARY KEY (id),
    KEY ix_login_events_subject_at (subject_type, subject_id, at),
    KEY ix_login_events_at (at),
    KEY ix_login_events_ip_at (ip, at),
    KEY ix_login_events_app_password (app_password_id),
    CONSTRAINT fk_login_events_app_password FOREIGN KEY (app_password_id) REFERENCES app_passwords (id) ON DELETE SET NULL,
    CONSTRAINT chk_login_events_country_format CHECK (country REGEXP '^[A-Z]{2}\\z')
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- One row per recipient of each Postfix log result. sender and recipient are utf8mb4_bin, so
-- an SMTPUTF8 address is kept as sent and the lowercase CHECK is exact. sender is empty for
-- a bounce. The domain ids, when the address is hosted, let domain admins search only their
-- own domains (17.12); they have no foreign key, so the history survives deleting a domain.
CREATE TABLE IF NOT EXISTS delivery_events (
    id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    queue_id VARCHAR(32) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    at DATETIME(3) NOT NULL,
    sender VARCHAR(254) CHARACTER SET utf8mb4 COLLATE utf8mb4_bin NOT NULL,
    recipient VARCHAR(254) CHARACTER SET utf8mb4 COLLATE utf8mb4_bin NOT NULL,
    status ENUM('sent', 'deferred', 'bounced', 'rejected', 'held', 'expired') NOT NULL,
    relay VARCHAR(255) CHARACTER SET ascii COLLATE ascii_bin NULL,
    dsn VARCHAR(16) CHARACTER SET ascii COLLATE ascii_bin NULL,
    reason VARCHAR(255) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci NULL,
    sender_domain_id INT UNSIGNED NULL,
    recipient_domain_id INT UNSIGNED NULL,
    PRIMARY KEY (id),
    KEY ix_delivery_events_at (at),
    KEY ix_delivery_events_sender_at (sender, at),
    KEY ix_delivery_events_recipient_at (recipient, at),
    KEY ix_delivery_events_sender_domain_at (sender_domain_id, at),
    KEY ix_delivery_events_recipient_domain_at (recipient_domain_id, at),
    KEY ix_delivery_events_queue_id (queue_id),
    CONSTRAINT chk_delivery_events_sender_lc CHECK (sender = LOWER(sender)),
    CONSTRAINT chk_delivery_events_recipient_lc CHECK (recipient = LOWER(recipient))
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Where each log reader stopped (a journald cursor), so no line is read twice.
CREATE TABLE IF NOT EXISTS log_cursors (
    source VARCHAR(32) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    cursor_value VARCHAR(512) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    PRIMARY KEY (source)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
