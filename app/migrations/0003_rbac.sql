-- 0003: roles, permissions, admins and the domains each admin may manage.
-- Seeds use INSERT IGNORE and resolve role ids by name, so re-running adds nothing twice.

CREATE TABLE IF NOT EXISTS roles (
    id INT UNSIGNED NOT NULL AUTO_INCREMENT,
    name VARCHAR(32) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    PRIMARY KEY (id),
    UNIQUE KEY uq_roles_name (name)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS role_permissions (
    role_id INT UNSIGNED NOT NULL,
    permission VARCHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    PRIMARY KEY (role_id, permission),
    CONSTRAINT fk_role_permissions_role FOREIGN KEY (role_id) REFERENCES roles (id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS admins (
    id INT UNSIGNED NOT NULL AUTO_INCREMENT,
    username VARCHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    email VARCHAR(254) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    password_hash VARCHAR(255) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    role_id INT UNSIGNED NOT NULL,
    mailbox_id INT UNSIGNED NULL,
    status ENUM('active', 'suspended') NOT NULL DEFAULT 'active',
    last_login_at DATETIME NULL,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (id),
    UNIQUE KEY uq_admins_username (username),
    KEY ix_admins_role (role_id),
    KEY ix_admins_mailbox (mailbox_id),
    CONSTRAINT fk_admins_role FOREIGN KEY (role_id) REFERENCES roles (id) ON DELETE RESTRICT,
    CONSTRAINT fk_admins_mailbox FOREIGN KEY (mailbox_id) REFERENCES mailboxes (id) ON DELETE SET NULL,
    CONSTRAINT chk_admins_username_format CHECK (username REGEXP '^[a-z0-9._-]{3,64}\\z'),
    CONSTRAINT chk_admins_email_lc CHECK (email = LOWER(email)),
    CONSTRAINT chk_admins_password_hash_prefix CHECK (password_hash LIKE '$argon2id$%' OR password_hash LIKE '$2y$%')
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS admin_domains (
    admin_id INT UNSIGNED NOT NULL,
    domain_id INT UNSIGNED NOT NULL,
    may_manage_universal_members BOOL NOT NULL DEFAULT 0,
    PRIMARY KEY (admin_id, domain_id),
    KEY ix_admin_domains_domain (domain_id),
    CONSTRAINT fk_admin_domains_admin FOREIGN KEY (admin_id) REFERENCES admins (id) ON DELETE CASCADE,
    CONSTRAINT fk_admin_domains_domain FOREIGN KEY (domain_id) REFERENCES domains (id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

INSERT IGNORE INTO roles (name) VALUES
    ('super_admin'),
    ('domain_admin');

INSERT IGNORE INTO role_permissions (role_id, permission)
SELECT r.id, p.permission
FROM roles r
JOIN (
    SELECT 'domain.manage' AS permission
    UNION ALL SELECT 'domain.view'
    UNION ALL SELECT 'mailbox.manage'
    UNION ALL SELECT 'alias.manage'
    UNION ALL SELECT 'forwarding.manage'
    UNION ALL SELECT 'list.domain.manage'
    UNION ALL SELECT 'list.universal.manage'
    UNION ALL SELECT 'filter.global.manage'
    UNION ALL SELECT 'filter.domain.manage'
    UNION ALL SELECT 'quarantine.manage'
    UNION ALL SELECT 'admin.manage'
    UNION ALL SELECT 'audit.read'
    UNION ALL SELECT 'system.configure'
) p
WHERE r.name = 'super_admin';

INSERT IGNORE INTO role_permissions (role_id, permission)
SELECT r.id, p.permission
FROM roles r
JOIN (
    SELECT 'domain.view' AS permission
    UNION ALL SELECT 'mailbox.manage'
    UNION ALL SELECT 'alias.manage'
    UNION ALL SELECT 'forwarding.manage'
    UNION ALL SELECT 'list.domain.manage'
    UNION ALL SELECT 'filter.domain.manage'
    UNION ALL SELECT 'audit.read'
) p
WHERE r.name = 'domain_admin';
