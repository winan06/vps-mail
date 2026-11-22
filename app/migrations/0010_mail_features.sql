-- 0010: mail rules, out-of-office, personal spam lists and shared-mailbox access
-- (spec 17.3, 17.4, 17.7, 17.8).
--
-- Every ascii column is ascii_bin. Sieve text: rule values and folder names are written into
-- the generated Sieve script as quoted strings (job sieve_compile), so besides the free-text
-- rule of 0007 they may not hold a double quote or a backslash
-- (NOT REGEXP '[[:cntrl:]"\\\\]', which PCRE reads as the class: control, quote, backslash).

-- The portal's rule builder, one row per rule, applied in position order. A header rule names
-- its header, and only a header rule does. A move rule names its folder, and only a move rule
-- does. Folders are relative to the mailbox root: they never start with "/", never contain
-- "..", never start or end with a space, and hold no IMAP wildcard ("*" or "%").
-- Dovecot's own mailbox-name checks and ACLs stay the real barrier; these keep the
-- generated script and the folder list predictable.
CREATE TABLE IF NOT EXISTS sieve_rules (
    id INT UNSIGNED NOT NULL AUTO_INCREMENT,
    mailbox_id INT UNSIGNED NOT NULL,
    position SMALLINT UNSIGNED NOT NULL,
    active BOOL NOT NULL DEFAULT 1,
    match_field ENUM('from', 'to_cc', 'subject', 'header') NOT NULL,
    header_name VARCHAR(64) CHARACTER SET ascii COLLATE ascii_bin NULL,
    match_type ENUM('contains', 'is') NOT NULL,
    match_value VARCHAR(255) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci NOT NULL,
    action ENUM('move', 'mark_read', 'flag', 'trash', 'stop') NOT NULL,
    folder VARCHAR(255) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci NULL,
    PRIMARY KEY (id),
    UNIQUE KEY uq_sieve_rules_mailbox_position (mailbox_id, position),
    CONSTRAINT fk_sieve_rules_mailbox FOREIGN KEY (mailbox_id) REFERENCES mailboxes (id) ON DELETE CASCADE,
    CONSTRAINT chk_sieve_rules_header_name_format CHECK (header_name REGEXP '^[A-Za-z0-9-]{1,64}\\z'),
    CONSTRAINT chk_sieve_rules_header_name_by_field CHECK ((match_field = 'header') = (header_name IS NOT NULL)),
    CONSTRAINT chk_sieve_rules_match_value_text CHECK (match_value <> '' AND match_value NOT REGEXP '[[:cntrl:]"\\\\]'),
    CONSTRAINT chk_sieve_rules_folder_text CHECK (
        folder <> ''
        AND folder NOT REGEXP '[[:cntrl:]"\\\\*%]'
        AND folder NOT REGEXP '^ | $'
        AND folder NOT LIKE '%..%'
        AND folder NOT LIKE '/%'
    ),
    CONSTRAINT chk_sieve_rules_folder_by_action CHECK ((action = 'move') = (folder IS NOT NULL))
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- One out-of-office setting per mailbox. Times are UTC; time_zone is the IANA zone the user
-- entered them in, kept so the portal can show them back. body is plain text, 1 to 4096
-- characters, with tab, newline and carriage return as its only control characters.
-- interval_days is how long before the same sender gets another reply.
-- subject and body may hold quotes, so sieve_compile must escape them as Sieve strings.
CREATE TABLE IF NOT EXISTS vacation_settings (
    mailbox_id INT UNSIGNED NOT NULL,
    enabled BOOL NOT NULL DEFAULT 0,
    starts_at DATETIME NULL,
    ends_at DATETIME NULL,
    subject VARCHAR(255) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci NOT NULL,
    body TEXT CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci NOT NULL,
    interval_days TINYINT UNSIGNED NOT NULL DEFAULT 7,
    time_zone VARCHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL DEFAULT 'UTC',
    updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    PRIMARY KEY (mailbox_id),
    CONSTRAINT fk_vacation_settings_mailbox FOREIGN KEY (mailbox_id) REFERENCES mailboxes (id) ON DELETE CASCADE,
    CONSTRAINT chk_vacation_settings_dates_ordered CHECK (starts_at IS NULL OR ends_at IS NULL OR ends_at > starts_at),
    CONSTRAINT chk_vacation_settings_subject_text CHECK (subject <> '' AND subject NOT REGEXP '[[:cntrl:]]'),
    CONSTRAINT chk_vacation_settings_body_length CHECK (CHAR_LENGTH(body) BETWEEN 1 AND 4096),
    CONSTRAINT chk_vacation_settings_body_text CHECK (body NOT REGEXP '[\\x00-\\x08\\x0B\\x0C\\x0E-\\x1F\\x7F]'),
    CONSTRAINT chk_vacation_settings_interval_range CHECK (interval_days BETWEEN 1 AND 30),
    CONSTRAINT chk_vacation_settings_time_zone_format CHECK (time_zone REGEXP '^[A-Za-z_]+(/[A-Za-z0-9_+-]+)*\\z')
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Per-mailbox allow and block entries: a full address, or "@" + domain for a whole domain, in
-- the address and domain formats of 0001 (the local part is simply optional). One entry per
-- pattern, so a sender is never allowed and blocked at once.
CREATE TABLE IF NOT EXISTS spam_sender_lists (
    id INT UNSIGNED NOT NULL AUTO_INCREMENT,
    mailbox_id INT UNSIGNED NOT NULL,
    list_type ENUM('allow', 'block') NOT NULL,
    pattern VARCHAR(254) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (id),
    UNIQUE KEY uq_spam_sender_lists_mailbox_pattern (mailbox_id, pattern),
    CONSTRAINT fk_spam_sender_lists_mailbox FOREIGN KEY (mailbox_id) REFERENCES mailboxes (id) ON DELETE CASCADE,
    CONSTRAINT chk_spam_sender_lists_pattern_lc CHECK (pattern = LOWER(pattern)),
    CONSTRAINT chk_spam_sender_lists_pattern_format CHECK (pattern REGEXP '^([a-z0-9_+-]+(\\.[a-z0-9_+-]+)*)?@[a-z0-9]([a-z0-9-]*[a-z0-9])?(\\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+\\z')
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Who may read and who may send as each shared mailbox. The table only refuses a mailbox
-- sharing with itself: that both mailboxes are in the same domain, that the first is shared
-- and the second personal, and that both are active is checked by every view that reads this
-- table (v_sender_login and v_shared_acl in 0013), so a bad row grants nothing, and by the app.
CREATE TABLE IF NOT EXISTS shared_access (
    shared_mailbox_id INT UNSIGNED NOT NULL,
    member_mailbox_id INT UNSIGNED NOT NULL,
    can_read BOOL NOT NULL DEFAULT 1,
    can_send BOOL NOT NULL DEFAULT 0,
    PRIMARY KEY (shared_mailbox_id, member_mailbox_id),
    KEY ix_shared_access_member (member_mailbox_id),
    CONSTRAINT fk_shared_access_shared FOREIGN KEY (shared_mailbox_id) REFERENCES mailboxes (id) ON DELETE CASCADE,
    CONSTRAINT fk_shared_access_member FOREIGN KEY (member_mailbox_id) REFERENCES mailboxes (id) ON DELETE CASCADE,
    CONSTRAINT chk_shared_access_not_self CHECK (shared_mailbox_id <> member_mailbox_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
