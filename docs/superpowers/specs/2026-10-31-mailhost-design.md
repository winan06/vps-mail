# Mailhost — Design Spec

**Date:** 2026-10-31
**Status:** Draft, awaiting review
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

Each step gets its own implementation plan, and each ends with its tests passing.

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
