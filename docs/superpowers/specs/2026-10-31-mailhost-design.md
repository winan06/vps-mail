# Mailhost — Design Spec

**Date:** 2026-10-31
**Status:** Step 1 built (branch step1-schema). §17 version 1 additions approved 2026-11-01 (including the FR-083 login-code deviation in 17.5).
**Source requirements:** "Multi-Domain Email Hosting and Management System" SRS (Postfix, Dovecot, Rspamd, ClamAV)
**Build approach:** New system, built from scratch.

---

## 1. Goal

Run a self-hosted mail service for several domains on one new Ubuntu VPS. Admins manage everything (domains, mailboxes, aliases, forwarding, lists, filtering) from a web dashboard. Users read mail only in Outlook, Thunderbird or phone apps over IMAP/SMTP, and use a small portal for passwords, recovery email, forwarding and list membership. There is **no webmail**, and no interface ever shows message content.

**Success means:** every test in SRS §10 passes, except the backup test, which is deferred (see §12).

## 2. Decisions

### 2.1 SRS §12 open decisions, resolved

| # | Topic | Decision |
|---|---|---|
| 1 | Database | MariaDB holds all records, including mailbox login records. |
| 2 | Filtering | Rspamd + ClamAV. No OpenDKIM or OpenDMARC; Rspamd does DKIM signing and SPF/DKIM/DMARC checks. |
| 3 | Portal login | Mailbox password + OTP sent to the recovery email. OTP alone is used only for password recovery. |
| 4 | Recovery email | Users can change it themselves. The new address must be verified by OTP, and the old address gets a notice. |
| 5 | Super-admin list sending | Allowed by default. A global setting can restrict it. |
| 6 | List membership | Admin-controlled. Each list has an optional `self_subscribe` flag. List owners can manage members of lists they own. |
| 7 | Quarantine | Admins can release or delete. They see envelope details and spam score only, never the subject or body. |
| 8 | External forwarding | Set at three levels: global (allow/deny), then domain (inherit/deny), then mailbox (inherit/deny). Each level can only tighten. |
| 9 | Retention | Suspended mailboxes and domains are kept 30 days, then archived and deleted. Archives are kept 90 days. Both periods are configurable. |
| 10 | Scale | Small: up to about 10 domains, about 200 mailboxes and a few thousand messages a day. |
| 11 | Availability | Single server. |
| 12 | Deployment | Mail services and web app on the same server. |

### 2.2 Other decisions

| Topic | Decision |
|---|---|
| Server | New dedicated VPS: Ubuntu 24.04 LTS, 2 vCPU, 4–6 GB RAM. Disk ≈ sum of quotas + 20%. |
| Backend | PHP 8.3, plain MVC. Composer packages: Twig (auto-escaping templates) and PHPMailer. No framework. |
| Rspamd source | Official Rspamd apt repo. Ubuntu's own package is outdated. |
| DNS resolver | Local Unbound. Public resolvers and Pi-hole get refused by DNSBL providers. |
| Admin access | Admin site reachable only over the WireGuard mesh. The VPS joins as a client. |
| List members | Hosted mailboxes only. No external addresses and no nested lists. |
| External forwarding | Rewritten with `postsrsd` (SRS) so SPF still passes at the destination. |
| Backups | Deferred. Not in version 1. |
| Addresses | Lowercase ASCII only. Local parts: letters, digits, `_ + -`, single dots between them. Domains: two or more labels. No catch-all aliases. No plus-addressing (`recipient_delimiter` unset) in version 1. |
| Lists as targets | Aliases and forwards may not point at a list; such rows are ignored, so list sender rules can't be bypassed. |

## 3. Hostnames and network

| Name | Example | Used for |
|---|---|---|
| `MAIL_HOST` | `mail.allovion.com` | MX target, IMAP/SMTP server for all domains, and the public portal |
| `ADMIN_HOST` | `mailadmin.allovion.com` | Admin dashboard. Pi-hole on the hub gives it a local DNS record pointing at the VPS's WireGuard IP. |

- **TLS:** `MAIL_HOST` gets a Let's Encrypt certificate via HTTP-01 (Nginx webroot). Postfix, Dovecot and Nginx share it. `ADMIN_HOST` gets its certificate via DNS-01 using the Cloudflare plugin, the same way as your other VPN-only sites. A Certbot deploy hook reloads Postfix, Dovecot and Nginx.
- **Public ports (ufw):** 25, 465, 587, 993, 80, 443.
- **Closed:** 110, 143, 3306, 6379, 11332–11334.
- **WireGuard only:** admin site on 443 (bound to `wg0`). SSH should also move to `wg0` once the mesh link works.
- **Required by pre-flight:** outbound port 25 works, and the PTR record matches `MAIL_HOST`.

## 4. Components

| Component | Job | Runs as |
|---|---|---|
| Postfix | Port 25 inbound (postscreen + smtpd), 587 STARTTLS, 465 implicit TLS. Looks up domains, mailboxes, aliases, forwarding and list members through MySQL maps. | postfix |
| postsrsd | Sender rewriting for mail forwarded to outside addresses | postsrsd |
| Dovecot | IMAP over TLS on 993, LMTP delivery, SASL auth for Postfix, quota and quota-status, Sieve + IMAPSieve | dovecot / vmail |
| Rspamd | Milter on `127.0.0.1:11332`: spam scoring, ClamAV calls, SPF/DKIM/DMARC checks, DKIM signing, per-user rate limits | _rspamd |
| ClamAV (clamd) | Virus scanning, called by Rspamd. Signatures updated by freshclam. | clamav |
| Redis | Rspamd storage (spam learning, rate limits, greylisting) and app rate-limit counters. Localhost only. | redis |
| Unbound | Local recursive DNS for Postfix and Rspamd | unbound |
| MariaDB 10.11 | Single source of truth | mysql |
| Nginx + PHP-FPM | Two sites, two FPM pools | `mailhost-admin`, `mailhost-portal` |
| `mailpolicy` | Postfix policy service for list sender rules and per-list size limits. PHP CLI, started per connection by Postfix `spawn`. | `mailpolicy` |
| `mailctl-deploy` | Root helper: applies config changes with validation and rollback, plus all other root-only tasks | root |
| `mailhost-status` | Root timer, every minute: writes the health status file and mailbox usage | root |
| fail2ban | Bans IPs after failed logins on Postfix SASL, Dovecot and the portal | root |

**Paths**
- `/var/vmail/<domain>/<user>/`: Maildir, owned by `vmail` (uid/gid 5000), mode 0700.
- `/opt/mailhost/app/`: PHP code.
- `/etc/mailhost/`: config and secrets. `app.env` is mode 0640, owned by root, group `mailhost`.
- `/etc/mailhost/local/`: admin overrides the installer never touches.
- `/var/lib/mailhost/known-good/`: config snapshots used for rollback.
- `/var/lib/mailhost/archive/`: archives of deleted mailboxes and domains (root only).
- `/run/mailhost/`: deploy trigger folder and `status.json`.

## 5. Data model

MariaDB, InnoDB, utf8mb4. Times are stored in UTC. Changes are applied by versioned SQL migrations in `app/migrations/`.

### 5.1 Tables

| Table | Key columns |
|---|---|
| `domains` | `id`, `name` (unique), `status` (active/suspended/deleting), `default_quota_mb`, `max_mailboxes`, `external_forwarding` (inherit/deny), `suspended_at`, `created_at` |
| `domain_aliases` | `alias_domain` (unique), `target_domain_id` |
| `dkim_keys` | `domain_id`, `selector`, `public_key`, `active`, `created_at`. Private keys are kept only on disk, in `/var/lib/rspamd/dkim/`. |
| `mailboxes` | `id`, `domain_id`, `local_part`, unique (`domain_id`, `local_part`), `password_hash` (Argon2id), `recovery_email`, `recovery_verified_at`, `status` (active/suspended/deleting), `quota_mb`, `quota_used_bytes`, `usage_updated_at`, `external_forwarding` (inherit/deny), `password_changed_at`, `suspended_at`, `created_at` |
| `aliases` | `id`, `domain_id`, `local_part` (never blank: catch-all aliases are not supported, so mail for a suspended or unknown address can never reach another user), `active` |
| `alias_targets` | `alias_id`, `destination` |
| `forwarding_rules` | `id`, `mailbox_id`, `destination`, `keep_copy`, `active`, `created_by` |
| `lists` | `id`, `local_part`, `domain_id` (the domain the address lives in), `scope` (domain/universal), `self_subscribe`, `max_message_kb`, `status` |
| `list_members` | `list_id`, `mailbox_id`, `status` (active/suspended), unique (`list_id`, `mailbox_id`) |
| `list_owners` | `list_id`, `mailbox_id` |
| `list_sender_rules` | `list_id`, `rule_type` (address/domain/role/any_authenticated), `value` |
| `admins` | `id`, `username`, `email` (where OTPs are sent), `password_hash`, `role_id`, `mailbox_id` (nullable, links the admin to a sending mailbox), `status`, `last_login_at` |
| `roles` | `id`, `name` (super_admin, domain_admin) |
| `role_permissions` | `role_id`, `permission`. Permissions match SRS §4.4, e.g. `mailbox.manage`, `list.universal.manage`, `audit.read`. |
| `admin_domains` | `admin_id`, `domain_id`, `may_manage_universal_members` |
| `filter_global` + `filter_policies` | `filter_global` is a single row with the global `tag_score`, `quarantine_score`, `reject_score`, `virus_action`, `unscannable_action` and the min/max bounds domains must stay within. `filter_policies` holds one row per domain with the same score and action columns. |
| `quarantine_items` | `queue_id`, `domain_id`, `envelope_from`, `envelope_to`, `score`, `reason` (symbol names), `size_bytes`, `held_at`, `status` (held/released/deleted) |
| `otp_codes` | `id`, `subject_type` (mailbox/admin), `subject_id`, `purpose` (login/recovery/verify_email), `code_hmac`, `target` (the new email for verify_email), `expires_at`, `attempts`, `used_at`, `request_ip` |
| `sessions` | `token_hash`, `subject_type`, `subject_id`, `created_at`, `last_seen_at`, `expires_at`, `ip`, `user_agent`, `revoked_at` |
| `audit_log` | `id`, `at`, `actor_type`, `actor_id`, `action`, `target_type`, `target_id`, `domain_id`, `ip`, `details` (JSON, never secrets) |
| `deployments` | `id`, `job_type`, `payload` (JSON), `status` (queued/running/applied/failed/rolled_back), `requested_by`, `created_at`, `finished_at`, `log` |
| `settings` | `key`, `value` (OTP lifetime, global forwarding switch, super-admin list override, retention days, and similar) |

### 5.2 Views used by mail services

The views include active rows only. Because Postfix and Dovecot read them on every lookup, a suspension takes effect immediately without any reload.

- `v_domains`: active domains plus active alias domains.
- `v_mailboxes`: address, maildir path, quota.
- `v_auth`: address and password hash with the `{ARGON2ID}` prefix, for Dovecot passdb.
- `v_aliases`: one row per (source → destination). It is the union of:
  - alias targets;
  - forwarding rules (`keep_copy` adds a row pointing back to the mailbox itself);
  - list expansions, one row per active member. Postfix MySQL maps join multiple rows with commas, so no GROUP_CONCAT is needed;
  - alias domains, one row per active mailbox of the target domain (`user@alias` → `user@target`), so unknown addresses at an alias domain are still rejected.
- `v_sender_login`: sending address → login names allowed to use it (the mailbox itself and its aliases).
- `v_rejected_recipients`: addresses that exist but must not receive mail (suspended or deleting mailboxes, suspended or empty lists, disabled or target-less aliases, and their alias-domain variants). Postfix uses it as `check_recipient_access`, so these are rejected at RCPT time with a clear reason.

### 5.3 Database users (least privilege)

| User | Used by | Grants |
|---|---|---|
| `mail_ro` | Postfix, Dovecot | SELECT on the six mail views only (`v_domains`, `v_mailboxes`, `v_auth`, `v_aliases`, `v_sender_login`, `v_rejected_recipients`) |
| `mail_policy` | `mailpolicy` | SELECT on `v_domains`, `v_lists`, `v_list_sender_rules`, `v_login_roles` and `settings`; column-level INSERT on `audit_log` (never `id` or `at`) |
| `mail_app` | Admin site | Read/write on app tables except `audit_log`; SELECT and column-level INSERT on `audit_log` (never `id` or `at`) |
| `mail_portal` | Portal | SELECT on `domains`, `mailboxes`, `lists`, `list_owners`, `settings`. UPDATE only on these mailbox columns: `password_hash`, `recovery_email`, `recovery_verified_at`, `password_changed_at`. Read/write on `forwarding_rules` and `list_members`. Sessions and OTP codes only through `v_portal_sessions` / `v_portal_otp_codes` (mailbox rows only, enforced by `WITH CHECK OPTION`). Jobs only through `v_portal_deployments` (`doveadm_kick`, requested by a mailbox). column-level INSERT on `audit_log` (never `id` or `at`). |
| `mailctl` | `mailctl-deploy`, `mailhost-status` | Read on everything. UPDATE on `deployments`, `quarantine_items`, the mailbox usage columns and `dkim_keys`. column-level INSERT on `audit_log` (never `id` or `at`). |

## 6. Mail flow

### 6.1 Inbound (port 25)

1. **postscreen:** pregreet test and DNSBL checks (`zen.spamhaus.org`) through local Unbound.
2. **smtpd restrictions:**
   - reject non-FQDN HELO and sender;
   - reject unknown recipients (`v_mailboxes` / `v_aliases`);
   - `reject_unauth_destination`, so there is no open relay (FR-033);
   - reject mail that has not logged in but uses a hosted domain as the envelope sender.
3. **`check_policy_service` → `mailpolicy`:** applies only when the recipient is a list (§7).
4. **`check_policy_service` → Dovecot quota-status:** a full mailbox is rejected during the SMTP conversation.
5. **Rspamd milter:** spam score, SPF/DKIM/DMARC checks, ClamAV scan. The action comes from `filter_policies`: add header, quarantine (hold queue) or reject.
   - Viruses are rejected during the SMTP conversation by default.
   - Encrypted or unscannable attachments (`AlertEncrypted`) are quarantined by default.
6. **LMTP → Dovecot → Maildir.**
   - A global Sieve script (`sieve_before`) files mail tagged as spam into `Junk`.
   - IMAPSieve trains Rspamd when a user moves mail into or out of `Junk`.

**Fail-closed:** `milter_default_action = tempfail`, and a ClamAV failure (`CLAM_VIRUS_FAIL`) forces a soft reject. Mail is never delivered unscanned (FR-045).

**Per-domain thresholds:** applied with Rspamd `settings` rules keyed on the recipient domain, which `mailctl-deploy` generates from `filter_policies`. A message to several hosted domains is scored once, so rules are ordered strictest first and mixed-recipient mail gets the strictest policy.

### 6.2 Submission (587 STARTTLS, 465 implicit TLS)

- **Login:** SASL via Dovecot, TLS required, no plaintext login on any unencrypted connection (FR-008, FR-032).
- **Sender check:** `smtpd_sender_login_maps = v_sender_login` with `reject_sender_login_mismatch`, so users send only as their own address or their aliases.
- **Rspamd on outbound:** ClamAV scan (FR-055), spam score, per-user rate limit, DKIM signing (FR-052).
- **Message size:** 25 MB default, set by a global setting (FR-074).

### 6.3 Forwarding

- **Storage:** forwarding rows are part of `v_aliases`. `keep_copy` decides whether the mailbox also keeps a copy (FR-040).
- **External destinations** go through `postsrsd`.
- **Loops (FR-041):** on save, the app follows the forwarding graph across hosted addresses and rejects any cycle. Postfix's `Delivered-To` loop detection catches loops through outside servers.
- **Restrictions (FR-042):** checked on save against global, domain and mailbox settings, and also enforced by `v_aliases` itself: an external forward only appears while all three levels allow it, so tightening any level stops existing forwards immediately.

### 6.4 Quarantine

- **Holding:** quarantined messages sit in Postfix's hold queue.
- **Syncing:** the `mailhost-status` timer reads the hold queue (envelope details and Rspamd score headers only) into `quarantine_items`.
- **Release and delete:** queued as `mailctl-deploy` jobs that run `postsuper -H` or `postsuper -d`.

## 7. Lists

- **Addresses:**
  - Domain lists use their own domain and are managed by that domain's admins.
  - Universal lists use any hosted domain the super-admin picks (for example `lists.allovion.com`) and are managed by super-admins only.
  - Domain admins can manage members from their own domains in a universal list only if `may_manage_universal_members` is set (FR-063).
- **Sender check at RCPT (FR-064 to FR-069):** Postfix sends `mailpolicy` the recipient, the sender, `sasl_username` and the client address. If the recipient is a list, the sender passes when any rule matches:
  - `address`: the envelope sender equals the value. If the address is hosted, the sender must also have logged in.
  - `domain`: the sender's domain equals the value, with the same login requirement for hosted domains.
  - `role`: `sasl_username` belongs to a mailbox linked to an admin with that role.
  - `any_authenticated`: `sasl_username` is present.
  - Super-admins pass unless `settings.superadmin_list_override = restrict`.
  - A pass returns `DUNNO`.
  - A fail returns `REJECT 5.7.1 Not authorised to send to this list` and adds an `audit_log` row. A Redis counter collapses repeated rejections from the same sender, so an attack can't flood the log (FR-066, FR-076).
- **Size check:** `mailpolicy` also runs at `smtpd_end_of_data_restrictions` to enforce `max_message_kb`, because the size is only known at that point.
- **Expansion:** Postfix expands the list via `v_aliases` and removes duplicate recipients itself (FR-071, FR-072). Members are always mailboxes, never lists, so recursion can't happen (FR-073).
- **Domain isolation:** the app only allows mailboxes from the list's own domain as members of a domain list (FR-078).
- **Shared rule code:** the sender-rule check is one PHP function used by both `mailpolicy` and the admin UI's "test sender" button.

## 8. Web app

### 8.1 Layout

```
app/
  public/admin/index.php     # front controller, admin pool
  public/portal/index.php    # front controller, portal pool
  src/Controller/{Admin,Portal}/
  src/Service/   Domain, Mailbox, Alias, Forwarding, List, SenderRules,
                 FilterPolicy, Quarantine, Otp, Auth, Session, Authz,
                 Audit, Deploy, Status
  src/Repo/      one PDO repository per table group
  templates/{admin,portal}/  # Twig, autoescape on
  migrations/
  bin/mailpolicy             # Postfix spawn entry point
  bin/mailhostctl            # CLI: create super-admin, run migrations
tests/                       # PHPUnit
```

### 8.2 Authorisation (fail-closed)

- **Checked first:** every controller action calls `Authz::require($permission, $resource)` before doing anything. If nothing grants the permission, the request is denied (403).
- **Domain taken from the database:** a resource's domain is loaded from the database by the resource's ID, never taken from the request (FR-016, §6.2 of the SRS).
- **Super-admin** is a role holding every permission. There are no special-case checks.
- **Portal actions** are limited to the logged-in mailbox, plus lists that mailbox owns (FR-090).

### 8.3 Login and OTP

- **Admin:** username + password + an OTP emailed to `admins.email`. Reachable over the VPN only.
- **Portal:** address + mailbox password + an OTP sent to the recovery email.
- **Recovery:** address, then an OTP to the recovery email, then a new password.
- **No address checks:** every login or recovery request gets the same reply: "If that account exists, a code has been sent." (FR-099).
- **OTP rules:**
  - 6 digits from `random_int` (FR-091).
  - Stored as HMAC-SHA256(server key, id ‖ code) (FR-096), and never logged (FR-097).
  - 10-minute lifetime, configurable (FR-093). 5 wrong tries kills the code.
  - Issuing a new code voids earlier ones for the same purpose (FR-098).
  - Single use, enforced with `UPDATE … SET used_at = NOW() WHERE id = ? AND used_at IS NULL` (FR-092).
  - Rate limits in Redis: 3 codes per 15 minutes per account, 10 per hour per IP, and verification attempts limited per code and per IP (FR-094, FR-095).
- **After a password reset:**
  - All of the user's portal sessions are revoked (FR-102).
  - A `doveadm kick` job is queued so connected mail clients have to log in again.
  - A security notice goes to the mailbox and the recovery address (FR-101).
- **Recovery email change:** an OTP is sent to the new address to verify it (FR-100), and the old address gets a notice.
- **Password hashes:**
  - PHP `password_hash(PASSWORD_ARGON2ID)`. The hash format is what Dovecot's `{ARGON2ID}` scheme reads.
  - Dovecot's `auth_cache` keeps reconnecting clients from re-hashing on every login.
  - Admins can reset a password but never read one (FR-025).
- **OTP email:** sent with PHPMailer to `127.0.0.1:587` over STARTTLS, logged in as a system mailbox (`noreply@<primary domain>`). Its credentials are stored in `app.env`.

### 8.4 Web security

- **Sessions:** stored in the `sessions` table. Cookie is `__Host-` prefixed, `Secure`, `HttpOnly` and `SameSite=Strict`. The ID changes on login.
- **Timeouts:** 30 minutes idle and 8 hours absolute for admins; 15 minutes idle and 1 hour absolute for the portal.
- **CSRF:** a token on every POST.
- **Headers:** CSP `default-src 'self'`, HSTS, `X-Frame-Options: DENY`, `X-Content-Type-Options: nosniff`, `Referrer-Policy: same-origin`.
- **Database and input:** PDO prepared statements only, with emulated prepares off. Every input goes through a validation layer with strict patterns for domains, local parts and addresses.
- **Login throttling:** Redis counters per account and per IP. fail2ban reads the portal's failed-login log.

### 8.5 Admin features (SRS §4.1, §4.2)

- Domains, including suspend, delete with a retention choice (FR-019), and DNS guidance (FR-053).
- Mailboxes, aliases, domain aliases and forwarding.
- Lists: members, owners and sender rules.
- Filter policies, within the global limits.
- Quarantine: release or delete.
- Audit log, with filters.
- Health dashboard, from `status.json`.
- Client setup instructions (FR-035).

**DNS guidance for each domain:** MX → `MAIL_HOST`; SPF `v=spf1 mx -all`; the DKIM TXT record built from `dkim_keys`; DMARC starting at `p=quarantine`.

## 9. Deploy and rollback (`mailctl-deploy`, SRS §6.4)

1. **Queue:** the app inserts a `deployments` row and creates a file in `/run/mailhost/deploy/`, a folder the app group can write to with the sticky bit set. PHP never runs shell commands.
2. **Trigger:** a systemd `.path` unit starts `mailctl-deploy.service` (oneshot, root). A one-minute timer is a backup trigger. `flock` makes sure only one helper runs at a time.
3. **Per job:**
   1. Re-validate the payload against a strict pattern for its job type.
   2. Snapshot the affected config to `known-good/<job-id>/`.
   3. Render the config from fixed templates.
   4. Validate it with `postfix check`, `doveconf -n` and `rspamadm configtest`.
   5. Apply it and reload only the affected service.
   6. Health-check the service (it is running and its port answers).
   7. Mark the job `applied`.
   8. On any failure: restore the snapshot, reload, mark the job `rolled_back` and save the log.
4. **Job types:**
   - `dkim_generate` (`rspamadm dkim_keygen`, 2048-bit);
   - `rspamd_policy` (global and per-domain settings);
   - `doveadm_kick`;
   - `quarantine_release` and `quarantine_delete`;
   - `domain_archive` and `mailbox_archive` (tar + zstd into `archive/`, then remove);
   - `retention_sweep` (daily: suspended for 30 days → archive; archives older than 90 days → delete).

## 10. Installer (`mailhost-install`, modular Bash)

- **Usage:** `mailhost-install --config /etc/mailhost/install.conf`, which sets `MAIL_HOST`, `ADMIN_HOST`, `PRIMARY_DOMAIN`, `ADMIN_EMAIL` and `CF_API_TOKEN_FILE`.
- **Pre-flight (stops on failure):**
  - Ubuntu 24.04 and at least 4 GB RAM;
  - `MAIL_HOST` is a full domain name and its A record points to this server;
  - PTR equals `MAIL_HOST`;
  - an outbound connection to a real MX on port 25 works;
  - `wg0` is up.
- **Modules (`lib/NN-name.sh`):** firewall → unbound → mariadb (+ migrations, DB users) → redis → postfix + postsrsd → dovecot → clamav → rspamd → nginx + php-fpm → certbot → app → mailctl-deploy + mailhost-status → fail2ban → report.
- **Safe to re-run (FR-010, FR-012):**
  - Each module checks the current state before acting.
  - Files are rendered to a temp path, validated, compared with what's there, backed up to `/var/lib/mailhost/install-backups/<timestamp>/`, then swapped in atomically.
  - Local changes go in `/etc/mailhost/local/` and in Rspamd's `local.d` and `override.d`, which the installer never overwrites.
- **Bootstrap (FR-009):** `mailhostctl admin create --super` prompts for a password. There are no default credentials.
- **Report (FR-013):** `/root/mailhost-install-report.txt` lists component versions, service status, listening ports and the DNS records each domain needs.

## 11. Monitoring (SRS §9.1, NFR-003, NFR-013)

- **`mailhost-status` timer, every minute:** writes `/run/mailhost/status.json` with:
  - whether Postfix, Dovecot, Rspamd, clamd, Redis, MariaDB and Unbound are running;
  - active and hold queue sizes;
  - disk and RAM use;
  - certificate expiry;
  - failed logins in the last hour;
  - Rspamd stats.
- **Every 15 minutes** it also updates mailbox usage from `doveadm quota get`.
- **Alerts:** an email to super-admins when a service is down, the certificate expires within 14 days, the disk is over 85% full, or the queue passes a threshold.
- **Auto-restart:** core services get systemd `Restart=on-failure` drop-ins.

## 12. Deferred: backups and restore

SRS §9.2, §9.3, NFR-008 and NFR-009 are **not in version 1**. Until they're built, a disk failure loses all mail, the database and the DKIM keys.

Planned design, for when the work resumes:
- **Tool:** restic, encrypted and incremental.
- **What it covers:** nightly copies of `/var/vmail`, a MariaDB dump, service config, DKIM keys, `/etc/letsencrypt` and `/etc/mailhost`.
- **Retention:** 7 daily, 4 weekly, 6 monthly.
- **Restore:** `mailhostctl restore db|mailbox|full`, plus a monthly restore test.
- **Password:** the restic password must also be kept off the server.
- **Destination:** to be decided.

## 13. Testing

- **PHPUnit:** `Authz` (including attempts to reach another domain), OTP (expiry, reuse, attempt limits, voiding), forwarding-loop detection, effective forwarding policy, list sender rules, and input validators.
- **`tests/acceptance/mailhost-acceptance`** (Bash) runs the SRS §10 tests:
  - SMTP with `swaks`, including the GTUBE spam test message and the EICAR virus test file;
  - IMAP and TLS with `openssl s_client`, plus a check that plaintext login is refused;
  - portal OTP and domain isolation with `curl`, expecting 403 across domains;
  - a DKIM signature check;
  - list sender tests, sending both logged in and anonymous;
  - a duplicate-recipient test.
  - The open-relay test runs from the hub server, so it comes from a real outside IP.
- **Manual checklist:** Outlook and Thunderbird send/receive.
- **Order:** build and test on a local Ubuntu 24.04 VM with a test domain first, then run the same installer on the VPS.

## 14. Build order

Each step gets its own implementation plan, and each ends with its tests passing. The version 1 additions (§17) add a step 1b and extend steps 2–8; see §17.15.

| # | Step | Done when |
|---|---|---|
| 1 | Schema, views, DB users, `mailhostctl migrate` | Migrations apply cleanly twice; grants verified |
| 2 | Installer core: pre-flight, firewall, Unbound, MariaDB, Redis, Postfix, postsrsd, Dovecot, Certbot | A mailbox inserted by SQL can send and receive over IMAP/SMTP; relay is rejected; plaintext login is denied |
| 3 | Filtering: ClamAV, Rspamd, Sieve, fail2ban | GTUBE and EICAR are handled; outbound mail is DKIM-signed; fail-closed works when clamd is stopped |
| 4 | `mailctl-deploy` + `mailhost-status` | A broken policy job rolls back; quarantine release and delete work |
| 5 | Admin app: auth, RBAC, domains, mailboxes, aliases, forwarding, filter policies, quarantine, audit, health | Domain isolation tests pass |
| 6 | Lists + `mailpolicy` | Universal list, sender allowlist and duplicate-recipient tests pass |
| 7 | Portal: OTP, recovery, password, recovery email, forwarding, lists | OTP and password-reset tests pass |
| 8 | Acceptance suite + hardening review | All of SRS §10 passes except backup |

## 15. Things to verify early

1. **Port 25 and PTR:** the VPS provider allows outbound port 25 and lets you set PTR. This blocks everything else.
2. **Argon2id in Dovecot:** Ubuntu 24.04's Dovecot supports the `{ARGON2ID}` scheme (needs libsodium). Fallback: `{BLF-CRYPT}` (bcrypt), which both PHP and Dovecot support.
3. **Quarantine via milter:** Rspamd's milter can send messages to Postfix's hold queue. Fallback: deliver quarantined mail to a restricted quarantine Maildir that only `mailctl-deploy` can read.
4. **Spamhaus limits:** Spamhaus free-use limits fit this volume. If not, switch to their DQS service.
5. **Cloudflare token:** a Cloudflare API token, limited to the DNS zone, for the `ADMIN_HOST` certificate.

## 16. SRS coverage

| SRS | Where |
|---|---|
| §4 actors and RBAC | §5.1 (`roles`, `admin_domains`), §8.2 |
| FR-001–013 installation | §10 |
| FR-014–028 domains and mailboxes | §5, §8.5, §9 (archive jobs) |
| FR-029–035 client access | §3, §6.2, §8.5 |
| FR-036–043 aliases and forwarding | §5.2, §6.3 |
| FR-044–057 filtering | §6.1, §6.2, §6.4, §9 |
| FR-058–080 lists | §7 |
| FR-081–102 portal and OTP | §8.3 |
| §6 security | §5.3, §8.2–8.4, §9 |
| §9.1 monitoring | §11 |
| §9.2–9.3 backup and recovery | §12 (deferred) |

## 17. Version 1 additions (added 2026-11-01)

Twelve features added after step 1. None of them adds webmail, and no interface shows message content. They follow the step 1 rules:
- lowercase ASCII addresses with the same format checks;
- column-level grants and `WITH CHECK OPTION` views for the portal;
- every change to mail routing goes through the SQL views and their tests.

New tables come in new migrations (0007 onward); 0001–0006 stay as reviewed.

### 17.1 Company directory (read-only CardDAV)

- **What:** each domain gets a read-only address book of its active mailboxes, with display name, job title, department and phone.
- **Data:** new mailbox columns `display_name`, `job_title`, `department`, `phone`, `directory_visible` (default on). Users edit their own in the portal, and admins edit any in their domains. The new view `v_directory` lists active, visible mailboxes in active domains, including shared mailboxes (17.8).
- **Server:** SabreDAV (Ubuntu package `php-sabre-dav`) inside the portal pool at `https://MAIL_HOST/dav/`, with a read-only backend over `v_directory`.
- **Login:** mailbox address plus an app password (17.5), or the main password if 2FA is off. A user only sees their own domain's book.
- **Mail apps:** Thunderbird, iPhone/Mac, and Android with DAVx⁵. Outlook desktop has no built-in CardDAV support.

### 17.2 One-click mail app setup

- **Thunderbird:** `https://autoconfig.<domain>/mail/config-v1.1.xml`.
- **Outlook:** `https://autodiscover.<domain>/autodiscover/autodiscover.xml` (IMAP/SMTP settings), plus an `_autodiscover._tcp.<domain>` SRV record as a fallback.
- **DNS and certificates:** `autoconfig.`, `autodiscover.` and `mta-sts.` (17.10) are CNAMEs to `MAIL_HOST` and appear in the DNS guidance (§8.5). Once they resolve, the `mailctl-deploy` job `domain_certs` adds them to a per-domain Let's Encrypt certificate via HTTP-01.
- **Portal setup page:**
  - an iPhone/Mac `.mobileconfig` profile (IMAP 993 + SMTP 587, no password inside);
  - a QR code that opens the same download;
  - the plain settings table (FR-035).
- **No address probing:** the same answer is returned for any address at a hosted domain, so these endpoints never reveal whether a mailbox exists.

### 17.3 Out-of-office replies

- **Portal form:** on/off, start and end date-time (stored in UTC, entered in the user's time zone), subject, plain-text message up to 4 KB, and the reply interval per sender (default 7 days).
- **How it runs:** Dovecot Pigeonhole `vacation`, inside the user's generated Sieve script (17.4).
- **Never replies to:** lists, bulk or auto-generated mail (`Auto-Submitted`, `Precedence: bulk/list/junk`), or `no-reply`-style senders.
- **Sending:** replies go out from the mailbox address through the normal outbound path, so they are DKIM-signed and rate-limited.

### 17.4 Mail rules

- **Portal rule builder:**
  - conditions: from, to/cc, subject, or header *contains* / *is*;
  - actions: move to folder, mark read, flag, move to Trash, stop processing.
  - Rules are stored in order in `sieve_rules`.
- **Compiling:** the `mailctl-deploy` job `sieve_compile` writes one script per mailbox (rules + out-of-office) to `/var/vmail/<domain>/<user>/sieve/mailhost.sieve` and compiles it with `sievec`.
- **Locked down:**
  - no user-written raw Sieve, and no ManageSieve (port 4190 stays closed);
  - the `redirect`, `enotify` and `vnd.dovecot.*` extensions are disabled for user scripts.
  - So rules can never forward mail around the forwarding policy. Forwarding exists only in `forwarding_rules`.
- **Order:** the global spam-to-Junk script (§6.1) still runs first.

### 17.5 App passwords and two-factor login

- **2FA:** optional authenticator-app codes (TOTP, RFC 6238: 6 digits, 30 s, ±1 step) for portal users and admins.
  - The secret is stored encrypted with a server key in `totp_secrets`.
  - Users get 10 single-use recovery codes, stored hashed.
  - A super-admin can require 2FA for all admins.
- **Which code at login:** a user with an authenticator app uses its code instead of the emailed code. Password recovery always uses the emailed code (FR-085).
  - ⚠️ **Deviation from FR-083**, which says the login code is emailed. Needs your approval.
- **App passwords:**
  - Stored in `app_passwords`: mailbox, name, Argon2id hash, created, last used, revoked.
  - Each is 16 random characters in 4 groups, shown once.
  - Dovecot checks app passwords first (`v_app_auth`), then the main password (`v_auth`).
- **With 2FA on**, `require_app_passwords` is set: `v_auth` leaves that mailbox out, so the main password no longer works for IMAP/SMTP/CardDAV, and a stolen main password can't read mail.
- **Revoking** an app password queues `doveadm_kick` for that mailbox.

### 17.6 Login activity and alerts

- **Recorded:** `login_events` holds who, when, service (imap, smtp, portal, admin, dav), result, IP, country, client name and the app password used. Kept 90 days.
- **Where it comes from:**
  - `mailhost-status` reads Dovecot and Postfix login lines from journald every minute, using a cursor so no line is read twice.
  - The portal, admin site and CardDAV write their own events directly.
- **Country:** from the DB-IP "IP to Country Lite" database (free, CC BY 4.0), refreshed monthly.
- **Portal:** "Recent activity" shows the last 30 days.
- **Alerts:** an email to the mailbox and recovery address on the first successful login from a new country, and when an app password is created. At most one alert per hour.
- **Sign out everywhere:** revokes portal sessions and queues `doveadm_kick`, with an option to also revoke all app passwords.

### 17.7 Personal spam controls

- **Lists:** `spam_sender_lists` holds, per mailbox, allow and block entries, each a full address or `@domain` in lowercase.
- **How they apply:** the `mailctl-deploy` job `spam_lists` writes Rspamd multimap files keyed by recipient and sender. Rspamd picks up map changes without a restart.
  - Allow lowers the spam score.
  - Block adds a high score, so the mail goes to Junk.
  - Neither ever bypasses virus scanning or a DMARC reject.
- **Daily digest:** each mailbox with quarantined mail in the last 24 h gets one email listing sender, time, size and reason. There is no subject, the same as `quarantine_items`.
- **Release requests:** each digest line has a "request release" link (single-use token, 7-day expiry) that creates a `release_requests` row. An admin approves it in the quarantine view, so release stays admin-only (§6.4).

### 17.8 Shared mailboxes

- **Kind:** `mailboxes.kind` is `personal` or `shared`. A CHECK makes sure shared mailboxes have no login password and no recovery email.
- **Access:** `shared_access` holds the shared mailbox, the member mailbox, `can_read` and `can_send`. Members must be from the same domain.
- **IMAP:** a Dovecot shared namespace plus the ACL plugin, with rights from the view `v_shared_acl`.
- **Sending as the shared address:** `v_sender_login` gains a row (shared address → member login) for every `can_send` member.
- **Delivery:** like any mailbox, because active shared mailboxes are in `v_mailboxes`. They are never in `v_auth`.
- **Managed by** domain admins (`mailbox.manage`).

### 17.9 Quota warnings

- **Thresholds:** 80%, 90% and 95% (in `settings`).
- **Warnings:** `mailhost-status` compares `quota_used_bytes` (refreshed every 15 minutes) and emails the user once per threshold. `quota_warned_level` resets when usage drops below 75%.
- **Portal:** a usage bar and a "Request more space" button. The request goes to `quota_requests` (mailbox, requested MB, note, status), and when an admin approves it the new quota applies.

### 17.10 Domain health checker

- **Checks:** every 6 hours, and on demand, `mailhost-status` checks each active domain:
  - MX points to `MAIL_HOST`;
  - SPF covers this server;
  - the DKIM TXT matches the active key;
  - DMARC record and policy;
  - autoconfig/autodiscover CNAMEs;
  - MTA-STS record and policy file, and TLS-RPT;
  - the server's PTR matches `MAIL_HOST`.
- **Results:** stored in `domain_checks` (domain, check, ok/warn/fail, detail, time). The admin view shows red/green with fix instructions.
- **MTA-STS:** `https://mta-sts.<domain>/.well-known/mta-sts.txt` is served by Nginx. It starts in `testing` mode and an admin switches it to `enforce`. TLS-RPT reports go to `tls-reports@PRIMARY_DOMAIN`.
- **DMARC reports:**
  - The DNS guidance sets `rua=mailto:dmarc-reports@PRIMARY_DOMAIN`, plus the `_report._dmarc` authorisation record for other hosted domains.
  - A timer parses the zipped or gzipped XML into `dmarc_reports` and `dmarc_records` (reporter, period, source IP, count, SPF/DKIM result), kept 180 days.
  - The admin view shows the pass rate per domain and the top failing senders.
  - This system mailbox is the only mail whose content the system reads.

### 17.11 Migration from an old provider

- **Migration job:** an admin enters the old IMAP host, port, TLS mode, username and password for a mailbox.
  - The password is stored encrypted in `migration_jobs` and deleted when the job ends, after 7 days at most.
  - The `mailctl-deploy` job `imap_migrate` runs `imapsync` into the new mailbox through a Dovecot master user that only this job can use.
  - The admin sees status and message counts only.
- **CSV bulk create:**
  - Columns: address, display name, quota, recovery email.
  - Every row is checked with the same address rules, then shown as a preview to confirm.
  - Initial passwords are random, shown once to the admin as a download, and `must_change_password` forces a change at first portal login.

### 17.12 Delivery log search

- **Recorded:** `mailhost-status` reads Postfix log lines (journald cursor) into `delivery_events`, one row per recipient: queue ID, time, sender, recipient, status (sent, deferred, bounced, rejected, held), relay host, DSN code and a short reason. Kept 30 days.
- **Search:** admins search by sender, recipient, time range and status. Domain admins only see events where the sender or recipient is in one of their domains. The search never shows subject or content.

### 17.13 New pieces at a glance

- **Tables:** `sieve_rules`, `vacation_settings`, `totp_secrets`, `recovery_codes`, `app_passwords`, `login_events`, `spam_sender_lists`, `release_requests`, `shared_access`, `quota_requests`, `domain_checks`, `dmarc_reports`, `dmarc_records`, `migration_jobs`, `delivery_events`.
- **Mailbox columns:** `display_name`, `job_title`, `department`, `phone`, `directory_visible`, `kind`, `require_app_passwords`, `quota_warned_level`, `must_change_password`.
- **Views:**
  - new: `v_directory`, `v_app_auth`, `v_shared_acl`;
  - updated: `v_auth` (no shared mailboxes; nothing with `require_app_passwords`), `v_mailboxes` (shared mailboxes included), `v_sender_login` (shared senders).
- **`mailctl-deploy` jobs:** `domain_certs`, `sieve_compile`, `spam_lists`, `imap_migrate`.
- **Packages:** `php-sabre-dav`, `dovecot-sieve`, `imapsync`, the DB-IP Lite country database.

### 17.14 Things to verify early (additions)

1. **Shared mailbox ACLs:** Dovecot reading shared-mailbox ACLs from SQL. Fallback: `mailctl-deploy` writes `dovecot-acl` files.
2. **imapsync:** whether it is packaged for Ubuntu 24.04. Fallback: the upstream release.
3. **Spam lists:** Rspamd multimap per-recipient allow/block with `rcpt` + `from` selectors.
4. **Outlook autodiscover:** whether the new Outlook still honours it for IMAP accounts. If not, the portal setup page covers it.

### 17.15 Where the additions land in the build order

| Step | Adds |
|---|---|
| **1b (new)** | Schema for all additions: migrations 0007+, the new and updated views, grants, tests (shared mailboxes, app-password-only login, directory). Done when migrations apply twice and every view and grant test passes. |
| 2 | Dovecot app-password passdb, shared namespace + ACL, Pigeonhole with restricted extensions |
| 3 | Per-user allow/block maps in Rspamd |
| 4 | Jobs `domain_certs`, `sieve_compile`, `spam_lists`, `imap_migrate`; login and delivery log ingest; GeoIP; quota warnings; domain checks; DMARC parsing; quarantine digest |
| 5 | Admin: shared mailboxes, directory fields, health and DMARC views, delivery search, CSV import + migration, quota and release approvals, admin 2FA |
| 7 | Portal: out-of-office, mail rules, app passwords + 2FA, activity + alerts, spam lists + release requests, quota bar + requests, setup page and profile, autoconfig/autodiscover endpoints, CardDAV directory |
| 8 | Acceptance tests for every addition |
