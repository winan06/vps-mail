-- 0002: mailing lists, their members, owners and sender rules.

-- max_message_kb NULL means the global limit applies.
CREATE TABLE IF NOT EXISTS lists (
    id INT UNSIGNED NOT NULL AUTO_INCREMENT,
    domain_id INT UNSIGNED NOT NULL,
    local_part VARCHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    scope ENUM('domain', 'universal') NOT NULL,
    self_subscribe BOOL NOT NULL DEFAULT 0,
    max_message_kb INT UNSIGNED NULL,
    status ENUM('active', 'suspended') NOT NULL DEFAULT 'active',
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (id),
    UNIQUE KEY uq_lists_domain_local_part (domain_id, local_part),
    CONSTRAINT fk_lists_domain FOREIGN KEY (domain_id) REFERENCES domains (id) ON DELETE CASCADE,
    CONSTRAINT chk_lists_local_part_lc CHECK (local_part = LOWER(local_part)),
    CONSTRAINT chk_lists_local_part_not_empty CHECK (local_part <> '')
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS list_members (
    list_id INT UNSIGNED NOT NULL,
    mailbox_id INT UNSIGNED NOT NULL,
    status ENUM('active', 'suspended') NOT NULL DEFAULT 'active',
    added_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (list_id, mailbox_id),
    KEY ix_list_members_mailbox (mailbox_id),
    CONSTRAINT fk_list_members_list FOREIGN KEY (list_id) REFERENCES lists (id) ON DELETE CASCADE,
    CONSTRAINT fk_list_members_mailbox FOREIGN KEY (mailbox_id) REFERENCES mailboxes (id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS list_owners (
    list_id INT UNSIGNED NOT NULL,
    mailbox_id INT UNSIGNED NOT NULL,
    PRIMARY KEY (list_id, mailbox_id),
    KEY ix_list_owners_mailbox (mailbox_id),
    CONSTRAINT fk_list_owners_list FOREIGN KEY (list_id) REFERENCES lists (id) ON DELETE CASCADE,
    CONSTRAINT fk_list_owners_mailbox FOREIGN KEY (mailbox_id) REFERENCES mailboxes (id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- value is empty exactly for the any_authenticated rule type.
CREATE TABLE IF NOT EXISTS list_sender_rules (
    id INT UNSIGNED NOT NULL AUTO_INCREMENT,
    list_id INT UNSIGNED NOT NULL,
    rule_type ENUM('address', 'domain', 'role', 'any_authenticated') NOT NULL,
    value VARCHAR(254) CHARACTER SET ascii COLLATE ascii_bin NOT NULL DEFAULT '',
    PRIMARY KEY (id),
    UNIQUE KEY uq_list_sender_rules_list_type_value (list_id, rule_type, value),
    CONSTRAINT fk_list_sender_rules_list FOREIGN KEY (list_id) REFERENCES lists (id) ON DELETE CASCADE,
    CONSTRAINT chk_list_sender_rules_value_lc CHECK (value = LOWER(value)),
    CONSTRAINT chk_list_sender_rules_value_by_type CHECK ((rule_type = 'any_authenticated') = (value = ''))
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
