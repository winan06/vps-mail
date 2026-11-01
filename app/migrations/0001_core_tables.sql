-- 0001: core tables for domains, mailboxes, aliases and forwarding.
--
-- Conventions for every table in 0001 to 0004:
--   * InnoDB, utf8mb4 / utf8mb4_unicode_ci by default.
--   * Identifier columns (domain names, local parts, addresses) are ascii_bin and
--     must be lowercase (CHECK col = LOWER(col)); callers lowercase before lookup.
--   * Times are UTC DATETIME values; every connection runs SET time_zone = '+00:00'.
--   * Safe to re-run: CREATE TABLE IF NOT EXISTS, and no row is ever overwritten.
--   * Format patterns end with \\z, not $: PCRE's $ also matches before a final newline.
--     The doubled backslash is SQL string escaping; the regex sees \z.
--   * Every column that holds a local part, a domain or an address uses the same pattern
--     (copied, since a migration cannot define constants):
--       local part  [a-z0-9_+-]+ atoms joined by single dots. No leading, trailing or double
--                   dot, so "." and ".." cannot occur: the maildir is <domain>/<local part>/,
--                   and those would point outside the domain's directory.
--       domain      labels [a-z0-9]([a-z0-9-]*[a-z0-9])? joined by single dots, at least two
--                   labels (no "localhost", no leading or trailing hyphen in a label).
--       address     local part @ domain. Exactly one @, and no comma, space, quote, angle
--                   bracket or backslash: Postfix splits a map result on commas, so a stored
--                   "me@gmail.com,all@example.com" would add a hidden second recipient.
--     The lowercase CHECK of a column comes before its format CHECK, so an uppercase value
--     is reported as a case error.

CREATE TABLE IF NOT EXISTS domains (
    id INT UNSIGNED NOT NULL AUTO_INCREMENT,
    name VARCHAR(253) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    status ENUM('active', 'suspended', 'deleting') NOT NULL DEFAULT 'active',
    default_quota_mb INT UNSIGNED NOT NULL DEFAULT 1024,
    max_mailboxes INT UNSIGNED NULL,
    external_forwarding ENUM('inherit', 'deny') NOT NULL DEFAULT 'inherit',
    suspended_at DATETIME NULL,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (id),
    UNIQUE KEY uq_domains_name (name),
    CONSTRAINT chk_domains_name_lc CHECK (name = LOWER(name)),
    CONSTRAINT chk_domains_name_format CHECK (name REGEXP '^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+\\z')
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS domain_aliases (
    id INT UNSIGNED NOT NULL AUTO_INCREMENT,
    alias_domain VARCHAR(253) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    target_domain_id INT UNSIGNED NOT NULL,
    PRIMARY KEY (id),
    UNIQUE KEY uq_domain_aliases_alias_domain (alias_domain),
    KEY ix_domain_aliases_target (target_domain_id),
    CONSTRAINT fk_domain_aliases_target FOREIGN KEY (target_domain_id) REFERENCES domains (id) ON DELETE CASCADE,
    CONSTRAINT chk_domain_aliases_alias_domain_lc CHECK (alias_domain = LOWER(alias_domain)),
    CONSTRAINT chk_domain_aliases_alias_domain_format CHECK (alias_domain REGEXP '^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+\\z')
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS dkim_keys (
    id INT UNSIGNED NOT NULL AUTO_INCREMENT,
    domain_id INT UNSIGNED NOT NULL,
    selector VARCHAR(63) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    public_key TEXT NOT NULL,
    active BOOL NOT NULL DEFAULT 0,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (id),
    UNIQUE KEY uq_dkim_keys_domain_selector (domain_id, selector),
    CONSTRAINT fk_dkim_keys_domain FOREIGN KEY (domain_id) REFERENCES domains (id) ON DELETE CASCADE,
    CONSTRAINT chk_dkim_keys_selector_lc CHECK (selector = LOWER(selector)),
    CONSTRAINT chk_dkim_keys_selector_format CHECK (selector REGEXP '^[a-z0-9-]+\\z')
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS mailboxes (
    id INT UNSIGNED NOT NULL AUTO_INCREMENT,
    domain_id INT UNSIGNED NOT NULL,
    local_part VARCHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    password_hash VARCHAR(255) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    recovery_email VARCHAR(254) CHARACTER SET ascii COLLATE ascii_bin NULL,
    recovery_verified_at DATETIME NULL,
    status ENUM('active', 'suspended', 'deleting') NOT NULL DEFAULT 'active',
    quota_mb INT UNSIGNED NOT NULL DEFAULT 1024,
    quota_used_bytes BIGINT UNSIGNED NULL,
    usage_updated_at DATETIME NULL,
    external_forwarding ENUM('inherit', 'deny') NOT NULL DEFAULT 'inherit',
    password_changed_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    suspended_at DATETIME NULL,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (id),
    UNIQUE KEY uq_mailboxes_domain_local_part (domain_id, local_part),
    CONSTRAINT fk_mailboxes_domain FOREIGN KEY (domain_id) REFERENCES domains (id) ON DELETE CASCADE,
    CONSTRAINT chk_mailboxes_local_part_lc CHECK (local_part = LOWER(local_part)),
    CONSTRAINT chk_mailboxes_local_part_format CHECK (local_part REGEXP '^[a-z0-9_+-]+(\\.[a-z0-9_+-]+)*\\z'),
    CONSTRAINT chk_mailboxes_password_hash_prefix CHECK (password_hash LIKE '$argon2id$%' OR password_hash LIKE '$2y$%'),
    CONSTRAINT chk_mailboxes_recovery_email_lc CHECK (recovery_email = LOWER(recovery_email)),
    CONSTRAINT chk_mailboxes_recovery_email_format CHECK (recovery_email REGEXP '^[a-z0-9_+-]+(\\.[a-z0-9_+-]+)*@[a-z0-9]([a-z0-9-]*[a-z0-9])?(\\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+\\z')
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- local_part is never empty: version 1 has no catch-all aliases, because a catch-all
-- would receive the mail of every address that is suspended, deleted or mistyped.
CREATE TABLE IF NOT EXISTS aliases (
    id INT UNSIGNED NOT NULL AUTO_INCREMENT,
    domain_id INT UNSIGNED NOT NULL,
    local_part VARCHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    active BOOL NOT NULL DEFAULT 1,
    PRIMARY KEY (id),
    UNIQUE KEY uq_aliases_domain_local_part (domain_id, local_part),
    CONSTRAINT fk_aliases_domain FOREIGN KEY (domain_id) REFERENCES domains (id) ON DELETE CASCADE,
    CONSTRAINT chk_aliases_local_part_lc CHECK (local_part = LOWER(local_part)),
    CONSTRAINT chk_aliases_local_part_not_empty CHECK (local_part <> ''),
    CONSTRAINT chk_aliases_local_part_format CHECK (local_part REGEXP '^[a-z0-9_+-]+(\\.[a-z0-9_+-]+)*\\z')
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS alias_targets (
    id INT UNSIGNED NOT NULL AUTO_INCREMENT,
    alias_id INT UNSIGNED NOT NULL,
    destination VARCHAR(254) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    PRIMARY KEY (id),
    UNIQUE KEY uq_alias_targets_alias_destination (alias_id, destination),
    CONSTRAINT fk_alias_targets_alias FOREIGN KEY (alias_id) REFERENCES aliases (id) ON DELETE CASCADE,
    CONSTRAINT chk_alias_targets_destination_lc CHECK (destination = LOWER(destination)),
    CONSTRAINT chk_alias_targets_destination_format CHECK (destination REGEXP '^[a-z0-9_+-]+(\\.[a-z0-9_+-]+)*@[a-z0-9]([a-z0-9-]*[a-z0-9])?(\\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+\\z')
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS forwarding_rules (
    id INT UNSIGNED NOT NULL AUTO_INCREMENT,
    mailbox_id INT UNSIGNED NOT NULL,
    destination VARCHAR(254) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    keep_copy BOOL NOT NULL DEFAULT 1,
    active BOOL NOT NULL DEFAULT 1,
    created_by_type ENUM('admin', 'mailbox') NOT NULL,
    created_by_id INT UNSIGNED NOT NULL,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (id),
    UNIQUE KEY uq_forwarding_rules_mailbox_destination (mailbox_id, destination),
    CONSTRAINT fk_forwarding_rules_mailbox FOREIGN KEY (mailbox_id) REFERENCES mailboxes (id) ON DELETE CASCADE,
    CONSTRAINT chk_forwarding_rules_destination_lc CHECK (destination = LOWER(destination)),
    CONSTRAINT chk_forwarding_rules_destination_format CHECK (destination REGEXP '^[a-z0-9_+-]+(\\.[a-z0-9_+-]+)*@[a-z0-9]([a-z0-9-]*[a-z0-9])?(\\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+\\z')
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
