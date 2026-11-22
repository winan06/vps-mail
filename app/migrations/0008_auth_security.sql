-- 0008: app passwords, authenticator-app (TOTP) secrets and recovery codes (spec 17.5).
--
-- Every ascii column is ascii_bin, so the lowercase and format CHECKs compare bytes and
-- cannot be passed by a value that differs only in case.

-- One row per app password of a mailbox. The password itself is shown once and stored only
-- as an Argon2id hash (app passwords are new, so there are no bcrypt hashes to carry over).
-- v_app_auth (0013) offers the rows with revoked_at IS NULL to Dovecot.
CREATE TABLE IF NOT EXISTS app_passwords (
    id INT UNSIGNED NOT NULL AUTO_INCREMENT,
    mailbox_id INT UNSIGNED NOT NULL,
    name VARCHAR(64) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci NOT NULL,
    password_hash VARCHAR(255) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    last_used_at DATETIME NULL,
    revoked_at DATETIME NULL,
    PRIMARY KEY (id),
    KEY ix_app_passwords_mailbox (mailbox_id),
    CONSTRAINT fk_app_passwords_mailbox FOREIGN KEY (mailbox_id) REFERENCES mailboxes (id) ON DELETE CASCADE,
    CONSTRAINT chk_app_passwords_name_text CHECK (name <> '' AND name NOT REGEXP '[[:cntrl:]]'),
    CONSTRAINT chk_app_passwords_password_hash_prefix CHECK (password_hash LIKE '$argon2id$%')
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- At most one authenticator secret per mailbox or admin. secret_enc is ciphertext: the app
-- encrypts the secret with a server key (steps 5 and 7), and the schema never sees it in clear.
-- confirmed_at is set once the first code has been checked. last_used_step is the 30-second
-- time step of the last accepted code, so the same code cannot be used twice (replay guard).
-- Like otp_codes and sessions, the subject has no foreign key: it is a mailbox or an admin.
CREATE TABLE IF NOT EXISTS totp_secrets (
    subject_type ENUM('mailbox', 'admin') NOT NULL,
    subject_id INT UNSIGNED NOT NULL,
    secret_enc VARBINARY(255) NOT NULL,
    confirmed_at DATETIME NULL,
    last_used_step BIGINT UNSIGNED NULL,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (subject_type, subject_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Single-use recovery codes, stored as lowercase hex SHA-256 hashes.
CREATE TABLE IF NOT EXISTS recovery_codes (
    id INT UNSIGNED NOT NULL AUTO_INCREMENT,
    subject_type ENUM('mailbox', 'admin') NOT NULL,
    subject_id INT UNSIGNED NOT NULL,
    code_hash CHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    used_at DATETIME NULL,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (id),
    UNIQUE KEY uq_recovery_codes_subject_code (subject_type, subject_id, code_hash),
    CONSTRAINT chk_recovery_codes_code_hash_lc CHECK (code_hash = LOWER(code_hash))
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
