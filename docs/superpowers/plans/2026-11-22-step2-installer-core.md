# Step 2: Installer Core Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** A re-runnable Bash installer that turns a fresh Ubuntu 24.04 server into a working IMAP/SMTP host for the domains and mailboxes in MariaDB. It covers pre-flight, firewall, Unbound, MariaDB, Redis, Postfix + postsrsd, Dovecot (app passwords, shared mailboxes, locked-down Sieve) and certificates.

**Architecture:** `installer/mailhost-install` loads `lib/common.sh`, then runs the numbered modules `lib/NN-name.sh` in order. Each module checks the current state first. It renders templates from `installer/templates/` and writes every file through one `install_file` path (compare, back up, atomic swap), validating the rendered files before they replace anything. It reloads a service only when one of that service's files changed. Postfix and Dovecot read domains, mailboxes and logins live from the step 1/1b views as `mail_ro`, so no domain or mailbox ever appears in a config file.

**Tech Stack:** Bash 5 (shellcheck 0.9 clean), bats 1.10, `envsubst` (gettext-base), Postfix 3.8.6 + postfix-mysql, postsrsd 1.10, Dovecot 2.3.21 (+ imapd, lmtpd, mysql, sieve), MariaDB 10.11, Redis 7.0, Unbound 1.19, Nginx 1.24, Certbot 2.9 + python3-certbot-dns-cloudflare, PHP 8.3 CLI + composer (for `mailhostctl`), swaks and `openssl s_client` for acceptance. Versions are the Ubuntu 24.04 candidates, checked 2026-11-22.

**Spec:** `docs/superpowers/specs/2026-10-31-mailhost-design.md`, mainly §3, §4, §6.1–6.3, §10, §13–15, §17.5, §17.8 and §17.14–17.15. This plan needs step 1b (PR #1) merged first, because Dovecot reads `v_app_auth` and `v_shared_acl`.

## Decisions this plan makes (need your OK)

These were checked against the Ubuntu 24.04 packages while writing:

1. **App passwords: 10 chained SQL passdbs.** Dovecot 2.3.21's SQL passdb fails when its query returns more than one row ("Password query returned multiple matches", checked in the `auth` binary), so `v_app_auth` cannot be one passdb. Dovecot tries ten SQL passdbs in turn (`ORDER BY app_password_id LIMIT 1 OFFSET 0` … `OFFSET 9`, each with `result_failure = continue`) and then the `v_auth` passdb. **A mailbox can use at most 10 live app passwords**, so the portal (step 7) must refuse an 11th. The alternative was a Lua passdb using lua-sql-mysql (both are packaged, and `password_verify` exists in Dovecot's Lua module). It would cost the same number of Argon2 checks per failed login, plus database connection handling in Lua.
2. **Argon2id is confirmed.** Hashes from PHP's `password_hash(PASSWORD_ARGON2ID)` verify under Dovecot's `{ARGON2ID}` scheme (checked with `doveadm pw -t`), so spec §15 item 2 needs no bcrypt fallback.
3. **`INSTALL_PROFILE=test` for the local VM (spec §13).** In the test profile, the network pre-flight checks (A record, PTR, outbound 25, `wg0`) warn instead of stopping the install, and certificates stay self-signed. Everything else is the same as production. `production` is the default and stays strict.
4. **SRS.** postsrsd 1.10 uses Postfix tcp tables on 127.0.0.1:10001/10002, and the SRS domain is `MAIL_HOST`. A MySQL map ahead of postsrsd returns hosted senders unchanged, so only senders outside the hosted domains are ever rewritten. Bounces to SRS addresses are checked at RCPT through postsrsd's reverse map (`local_recipient_maps`). A forged SRS address is therefore refused during the SMTP conversation instead of bounced, which avoids backscatter.
5. **RAM pre-flight: `MemTotal` ≥ 3,700,000 kB.** A "4 GB" VPS reports about 3.8 GiB, so a strict 4 GiB check would refuse it.
6. **Redis gets a generated password** (`requirepass`), even though it only listens on localhost.
7. **The installer owns `main.cf`, `master.cf`, `dovecot.conf` and `redis.conf` completely.** Ubuntu's `/etc/dovecot/conf.d` is never loaded, so its PAM passdb can't let system users into IMAP. Local changes go in `/etc/mailhost/local/postfix-main.cf` (appended to `main.cf`, so its lines win) and `/etc/mailhost/local/dovecot/*.conf` (`!include_try`).
8. **The IMAP folder separator is `/`**, matching the rule examples in 17.4. Task 9 checks whether Maildir++ accepts a `.` in folder names and records the answer for step 7's folder picker.
9. **Shared-mailbox rights are written as `dovecot-acl` files**, the 17.14 fallback, because Dovecot 2.3 has no SQL ACL backend. The list of mailboxes shared with each member comes live from SQL (`acl_shared_dict` reads `v_shared_acl`). The rights files are written by `mailhost-shared-acl-sync`, which runs every minute and will also run on every change from step 4. Removing someone's access therefore takes effect within about 90 seconds: up to 60 s for the sync plus Dovecot's 30 s ACL cache.
10. **Step 2 has no spam or virus scanning; that's step 3.** Run it on the test VM, or with MX not pointing at it. Never accept real mail before step 3 is installed (FR-045).

**Findings for later steps:** `imapsync` isn't packaged for 24.04, so step 4 needs the upstream release (17.14 item 2). `php-sabre-dav` in 24.04 is 1.8.12, so step 7 must check it covers 17.1 or install SabreDAV 4 through composer. `python3-certbot-dns-cloudflare` (2.0.0) is older than certbot (2.9.0); Task 7 checks they work together.

## Global Constraints

- Target: Ubuntu 24.04 LTS, run as root. Scripts: `#!/usr/bin/env bash`, `set -Eeuo pipefail`, `shellcheck -x` clean.
- Usage: `mailhost-install --config /etc/mailhost/install.conf [--only <module>]`. Config keys: `MAIL_HOST`, `ADMIN_HOST`, `PRIMARY_DOMAIN`, `ADMIN_EMAIL`, `CF_API_TOKEN_FILE` (spec §10), plus `INSTALL_PROFILE` (`production` | `test`, default `production`). An unknown key stops the install.
- Modules, in this order: `00-preflight`, `05-tls-bootstrap`, `10-firewall`, `20-unbound`, `30-mariadb`, `40-redis`, `50-postfix`, `60-dovecot`, `80-nginx`, `85-certbot`, `99-report`. The gaps are for later steps: `70-clamav`, `75-rspamd` and `95-fail2ban` (step 3), `88-app` and `90-mailctl` (steps 4–5).
- Safe to re-run (FR-010, FR-012): every file goes through `install_file`. A second run with the same config changes no file, restarts no service, creates no backup directory and generates no secret. Backups go to `/var/lib/mailhost/install-backups/<RUN_ID>/<original path>`, where `RUN_ID` is the UTC time `YYYYmmddTHHMMSSZ`.
- Never overwritten: anything under `/etc/mailhost/local/`, or a secret that already exists (`/etc/mailhost/db.env`, `/etc/mailhost/redis.pass`, `/etc/postsrsd.secret`).
- Secrets: `openssl rand -hex 24` (48 characters, which fits `mailhostctl`'s 24–128 rule). Files are mode 0600, or 0640 with the reading service's group. A secret never appears in the log, the report, or a command line (`ps`): mysql gets it from a `--defaults-extra-file`, redis-cli from `REDISCLI_AUTH`.
- Public TCP ports: 25, 465, 587, 993, 80, 443, plus 22 until SSH moves to `wg0`. Closed: 110, 143, 3306, 6379, 11332–11334. No POP3, no IMAP on 143, no ManageSieve (4190).
- Mail store: `/var/vmail/<domain>/<user>/` Maildir, owned by `vmail` (uid/gid 5000), mode 0700.
- Postfix and Dovecot use only the `mail_ro` account and these view columns: `v_domains(name)`, `v_mailboxes(email, maildir, quota_mb)`, `v_aliases(source, destination)`, `v_sender_login(sender, login)`, `v_rejected_recipients(email, reason)`, `v_auth(email, password)`, `v_app_auth(email, password, app_password_id)`, `v_shared_acl(shared_email, shared_maildir, member_login, rights)`.
- Every Postfix MySQL map is `proxy:mysql:` with `hosts = unix:/run/mysqld/mysqld.sock`, because chrooted smtpd and cleanup can't reach the socket.
- TLS: one pair for `MAIL_HOST` at `/etc/mailhost/tls/fullchain.pem` and `/etc/mailhost/tls/privkey.pem`. These are symlinks: to the self-signed pair at first, then to the Let's Encrypt live files after `85-certbot`. Postfix, Dovecot and Nginx all use it. TLS 1.2 or higher only. No plaintext login on any unencrypted connection (FR-008, FR-032).
- No plus-addressing: Postfix `recipient_delimiter` is unset, and Dovecot sets `recipient_delimiter =` empty.
- Message size: `settings.max_message_mb` (seeded at 25) × 1048576 sets Postfix's `message_size_limit`.
- No default credentials anywhere (FR-009).
- Output: one line per file, `changed <path>` or `unchanged <path>`, plus `reloaded <service>`. The full log goes to `/var/log/mailhost-install.log`.

## Testing layers

- **Unit (bats):** `installer/tests/unit/*.bats` runs anywhere without root. System commands are stubbed by putting fakes first on `PATH`, using `stub <cmd> <exit> [stdout]` from `tests/unit/helpers.bash`; each stub appends its arguments to `$STUB_LOG`. Validator-backed tests (`postconf -c`, `doveconf -c`, `unbound-checkconf`, `nginx -t`) skip when the package isn't installed.
- **Acceptance:** `installer/tests/acceptance/step2-acceptance.sh` runs as root after a full install. It loads its own fixture by SQL (`fixture.sh up` / `down`) and prints `PASS`, `FAIL` or `SKIP <reason>` for each numbered check, exiting 1 on any `FAIL`. It runs in two places:
  - **An agent workspace without systemd.** Services start through `service`. In the test profile, the firewall module skips with a warning when netfilter is unavailable. The DNS checks print `SKIP` when Unbound can't reach the root servers.
  - **Your Ubuntu 24.04 VM.** Every check runs, plus the open-relay check from another machine.
- **Fixture:** hosted domains `example.test` and `other.test`; `example.net` stands in for the outside world. Mailboxes `alice`, `bob` (suspended), `carol`, `dave` (`require_app_passwords = 1`) and `support` (shared: alice can read and send, carol can only read) at `example.test`, plus `erin@other.test` (other domain, active). Passwords and app passwords are random per run, hashed with PHP `password_hash` and inserted by root.
- **Step 2 is done when:** the bats suite passes, shellcheck is clean, and acceptance passes with no `FAIL` in the workspace and with no `FAIL` or `SKIP` on the VM.

## Review Focus

1. **A re-run changes nothing.** A second run with the same config must leave every file `unchanged`, reload nothing, create no backup directory and keep every secret. Pinned by acceptance C24 (Task 12).
2. **The firewall never locks out SSH.** OpenSSH is allowed before `ufw --force enable`, and the module never resets or deletes rules. Pinned by bats in Task 3.
3. **A revoked app password keeps working from Dovecot's auth cache.** After `revoked_at` is set and `doveadm auth cache flush <user>` runs, the password must fail. Pinned by acceptance C14 (Task 9). Step 4's `doveadm_kick` must flush the cache too.
4. **A real 4 GB VPS fails the RAM check.** `MemTotal: 3880000 kB` must pass and `3600000 kB` must fail. Pinned by bats in Task 2.
5. **Mail from a subdomain of a hosted domain gets rejected as forged.** For example, a newsletter sending from `bounce@news.example.test` when `example.test` is hosted. The hosted-sender check must match the exact domain only (`parent_domain_matches_subdomains` without `smtpd_access_maps`). Pinned by acceptance C12 (Task 8).

---

### Task 1: Installer skeleton and common library

**Files:**
- Create: `installer/mailhost-install`, `installer/lib/common.sh`, `installer/install.conf.example`, `installer/README.md`
- Test: `installer/tests/unit/helpers.bash`, `installer/tests/unit/common.bats`

**Interfaces:**
- Produces (`lib/common.sh`; every later module uses these):
  - `log_info MSG`, `log_warn MSG`, `die MSG` (exit 1). All write to stderr and to `$MAILHOST_LOG` (default `/var/log/mailhost-install.log`).
  - `load_config FILE`: parses `KEY=value` lines (blank lines and `#` comments allowed, optional surrounding double quotes) **without sourcing the file**. It validates every value, then exports the keys read-only. Formats:
    - `MAIL_HOST`, `ADMIN_HOST` and `PRIMARY_DOMAIN` use the 0001 domain pattern `^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+$`.
    - `ADMIN_EMAIL` is a local part `^[a-z0-9_+-]+(\.[a-z0-9_+-]+)*$`, then `@`, then that domain pattern.
    - `CF_API_TOKEN_FILE` must be an existing file of mode 0600 or stricter, in production only.
    - `INSTALL_PROFILE` is `production` or `test`.
  - `is_test_profile` returns 0 when `INSTALL_PROFILE=test`.
  - `render_template TEMPLATE OUT VAR...`: runs `envsubst` with only the listed variables. It dies if a listed variable is empty. Postfix `$name`, Dovecot `%u` and `%%h` pass through untouched.
  - `install_file SRC DEST MODE OWNER:GROUP` prints `changed DEST` or `unchanged DEST`, and adds a changed file to the array `MAILHOST_CHANGED`. It compares with `cmp`. On a change it backs the old file up to `$MAILHOST_BACKUP_ROOT/$RUN_ID/DEST`, creating that directory only on the first backup, then moves a temp file from DEST's own directory into place, with mode and owner already set.
  - `file_changed DEST` returns 0 if DEST is in `MAILHOST_CHANGED`. `restore_backup DEST` puts back this run's backup of DEST, or removes DEST if it was new.
  - `ensure_secret FILE [MODE OWNER:GROUP]` creates FILE with `openssl rand -hex 24` only if it doesn't exist. `secret_value FILE` prints it.
  - `pkg_install PKG...` runs `apt-get install -y --no-install-recommends` (`DEBIAN_FRONTEND=noninteractive`) for the packages `dpkg-query -W -f='${Status}'` doesn't report as installed, and does nothing if all are installed.
  - `svc_enable_now NAME`, `svc_reload NAME`, `svc_restart NAME`, `svc_is_active NAME` use `systemctl` when `$MAILHOST_SYSTEMD_DIR` (default `/run/systemd/system`) exists, and `service NAME start|reload|restart|status` otherwise. Each prints `reloaded NAME` or `restarted NAME`.
- Produces (`mailhost-install`): options `--config FILE` (required), `--only NAME` (run one module) and `--help`. It must run as root. It sets `RUN_ID`, loads the modules in numeric order, and calls `module_<name>` for each, where `<name>` is the file name without its number, with `-` turned into `_`.

- [ ] **Step 1: Write the failing tests** in `common.bats`. Each test sets `MAILHOST_LOG`, `MAILHOST_BACKUP_ROOT` and stubs to temp paths.

```bash
@test "load_config accepts the example file" {
  run load_config "$BATS_TEST_DIRNAME/../../install.conf.example"; [ "$status" -eq 0 ]; }
@test "load_config rejects an unknown key" {
  printf 'FOO=1\n' >> "$CONF"; run load_config "$CONF"; [ "$status" -eq 1 ]; [[ "$output" == *"unknown key FOO"* ]]; }
@test "load_config never executes a value" {
  sed -i 's/^MAIL_HOST=.*/MAIL_HOST=$(touch '"$BATS_TEST_TMPDIR"'\/pwned)mail.example.com/' "$CONF"
  run load_config "$CONF"; [ "$status" -eq 1 ]; [ ! -e "$BATS_TEST_TMPDIR/pwned" ]; }
@test "load_config: MAIL_HOST must be a lowercase FQDN" # cases: "mail", "Mail.example.com", "mail.example.com." → status 1
@test "load_config: CF_API_TOKEN_FILE required in production, not in test"
@test "render_template substitutes only the listed variables" {
  printf 'a=${MAIL_HOST} b=$myhostname c=%%u d=${OTHER}\n' > "$T"; MAIL_HOST=mail.example.com OTHER=x
  render_template "$T" "$OUT" MAIL_HOST; [ "$(cat "$OUT")" = 'a=mail.example.com b=$myhostname c=%u d=${OTHER}' ]; }
@test "render_template dies on an empty listed variable"
@test "install_file: identical content is unchanged and makes no backup" # output "unchanged …", no $MAILHOST_BACKUP_ROOT dir
@test "install_file: changed content is backed up, swapped, and recorded" # backup holds old bytes; file_changed DEST → 0
@test "restore_backup puts the old file back"
@test "ensure_secret keeps an existing secret" # sha256 equal before/after second call; mode 0600
@test "pkg_install calls apt-get only for missing packages" # stub dpkg-query 'install ok installed' → apt-get not in $STUB_LOG
@test "svc_reload falls back to service without systemd" # MAILHOST_SYSTEMD_DIR=/nonexistent → STUB_LOG has "service postfix reload"
```

- [ ] **Step 2: Run them and watch them fail.**
  Run: `bats installer/tests/unit/common.bats`
  Expected: every test fails (`common.sh` doesn't exist yet).
- [ ] **Step 3: Implement `lib/common.sh`, `mailhost-install` and `install.conf.example`** to the interfaces above. `README.md` covers running on the VM (test profile), the agent-workspace limits, and how to run the bats and acceptance suites.
- [ ] **Step 4: Run them and watch them pass, and run shellcheck.**
  Run: `bats installer/tests/unit/common.bats && shellcheck -x installer/mailhost-install installer/lib/*.sh`
  Expected: all tests `ok`; shellcheck prints nothing.
- [ ] **Step 5: Commit.** `git add installer && git commit -m "feat(installer): skeleton, config loader and safe file install"`

### Task 2: Pre-flight (`00-preflight.sh`)

**Files:** Create `installer/lib/00-preflight.sh`. Test: `installer/tests/unit/preflight.bats`.

**Interfaces:**
- Consumes: `load_config`, `is_test_profile`, `log_*`, `die`, `pkg_install`.
- Produces `module_preflight`. It first runs `pkg_install bind9-dnsutils iproute2`, then all six checks below, and only then decides. Each check prints `PASS <check>` or `FAIL <check>: <reason>`.
  - OS and RAM are always fatal.
  - In production, any failure stops the install with every failure listed.
  - In the test profile, the network checks become `WARN` lines and the install continues.
- Checks (data sources can be overridden for tests):
  - `check_os`: `VERSION_ID="24.04"` and `ID=ubuntu` in `${MAILHOST_OS_RELEASE:-/etc/os-release}`.
  - `check_ram`: `MemTotal` ≥ 3700000 kB in `${MAILHOST_MEMINFO:-/proc/meminfo}` (decision 5).
  - `check_mail_host_a`: `dig +short A "$MAIL_HOST"` must include one of the addresses from `ip -4 -o addr show scope global`. A NAT'd host fails this check; the README says so.
  - `check_ptr`: `dig +short -x <that address>` must equal `"$MAIL_HOST."`.
  - `check_outbound_25`: within `timeout 10`, open `/dev/tcp/gmail-smtp-in.l.google.com/25` and read a line starting with `220`.
  - `check_wg0`: `ip -o link show wg0` exists, with state `UP` or `UNKNOWN` (WireGuard shows `UNKNOWN`).

- [ ] **Step 1: Write the failing tests** (stub `dig`, `ip` and `timeout`; fixture os-release and meminfo files):
  - `os: 24.04 passes, 22.04 fails`
  - `ram: 3880000 kB passes, 3600000 kB fails`
  - `a record: local address passes, foreign address fails, no record fails`
  - `ptr: "$MAIL_HOST." passes, other name fails`
  - `outbound 25: a 220 banner passes, a timeout fails`
  - `wg0: missing fails`
  - `production: one network failure stops and lists every failure`: status 1, and the output contains both `FAIL ptr` and `FAIL wg0`.
  - `test profile: network failures warn and continue`: status 0, and the output contains `WARN ptr`.
  - `test profile: wrong OS still stops`: status 1.
- [ ] **Step 2: Run them and watch them fail.** Run: `bats installer/tests/unit/preflight.bats`. Expected: all fail.
- [ ] **Step 3: Implement `00-preflight.sh`.**
- [ ] **Step 4: Run them and watch them pass, then run shellcheck.** Expected: all `ok`; shellcheck clean.
- [ ] **Step 5: Commit.** `git commit -m "feat(installer): pre-flight checks with a test profile"`

### Task 3: Firewall (`10-firewall.sh`)

**Files:** Create `installer/lib/10-firewall.sh`. Test: `installer/tests/unit/firewall.bats`.

**Interfaces:** Produces `module_firewall`. It installs `ufw`, then runs, in this order:
1. `ufw default deny incoming` and `ufw default allow outgoing`;
2. `ufw allow OpenSSH`;
3. `ufw allow <port>/tcp` for 25, 465, 587, 993, 80 and 443;
4. `ufw --force enable`.

It never calls `ufw reset` or `ufw delete`; `ufw allow` is already idempotent. If `ufw status` fails because netfilter is unavailable (a container), the test profile gets `log_warn` and a skip, and production gets `die`.

- [ ] **Step 1: Write the failing tests** (stub `ufw`, which records its calls):
  - `allows OpenSSH before enabling`: in `$STUB_LOG`, the line number of `allow OpenSSH` is less than that of `--force enable`.
  - `opens exactly 25 465 587 993 80 443 and OpenSSH`: the set of `allow` arguments equals `{OpenSSH, 25/tcp, 465/tcp, 587/tcp, 993/tcp, 80/tcp, 443/tcp}`.
  - `never resets or deletes rules`: `$STUB_LOG` has no `reset` or `delete`.
  - `no netfilter: warns in test, dies in production`.
- [ ] **Step 2: Run them and watch them fail.** Expected: all fail.
- [ ] **Step 3: Implement `10-firewall.sh`.**
- [ ] **Step 4: Run them and watch them pass, then run shellcheck.**
- [ ] **Step 5: Commit.** `git commit -m "feat(installer): ufw rules without SSH lock-out"`

### Task 4: Unbound (`20-unbound.sh`)

**Files:** Create `installer/lib/20-unbound.sh`, `installer/templates/unbound/mailhost.conf` and `installer/templates/systemd/resolved-mailhost.conf`. Test: `installer/tests/unit/unbound.bats`.

**Interfaces:** Produces `module_unbound`.
- It writes `/etc/unbound/unbound.conf.d/mailhost.conf` (0644). That file is a `server:` clause with:
  - `interface: 127.0.0.1` and `interface: ::1`, port 53;
  - `access-control` allowing 127.0.0.0/8 and ::1 only;
  - `hide-identity: yes`, `hide-version: yes`, `qname-minimisation: yes`, `prefetch: yes`, `harden-dnssec-stripped: yes`.

  Ubuntu's root trust-anchor snippet stays as shipped. The candidate file is validated on its own with `unbound-checkconf <file>` before the swap.
- With systemd, it also writes `/etc/systemd/resolved.conf.d/mailhost.conf` with `DNS=127.0.0.1`, `Domains=~.` and `DNSStubListener=yes`, and restarts `systemd-resolved` if that file changed. Postfix's chroot copy of `resolv.conf` (127.0.0.53) then reaches Unbound through resolved, while Unbound does the recursion from this server's own IP (spec §2.2). Without systemd, `resolv.conf` is left alone.

- [ ] **Step 1: Write the failing tests:**
  - `rendered config passes unbound-checkconf` (skip if unbound is absent);
  - `listens on loopback only`: the only `interface:` values are `127.0.0.1` and `::1`;
  - `resolved drop-in only with systemd`.
- [ ] **Step 2: Run them and watch them fail.**
- [ ] **Step 3: Implement it.** On a changed file, `svc_enable_now unbound` the first time, `svc_reload unbound` afterwards.
- [ ] **Step 4: Run them and watch them pass, then run shellcheck.**
- [ ] **Step 5: Verify on the VM** (the workspace prints SKIP if the root servers can't be reached):
  - Run `dig +short @127.0.0.1 2.0.0.127.zen.spamhaus.org`. Expected: answers in `127.0.0.x`, never `127.255.255.x` (Spamhaus's "public resolver refused" code).
  - Run `ss -lunpH 'sport = :53'`. Expected: unbound on 127.0.0.1 and ::1, and systemd-resolved still on 127.0.0.53.
- [ ] **Step 6: Commit.** `git commit -m "feat(installer): local Unbound resolver"`

### Task 5: MariaDB, `mailhostctl`, schema and accounts (`30-mariadb.sh`)

**Files:** Create `installer/lib/30-mariadb.sh` and `installer/templates/mariadb/90-mailhost.cnf`. Test: `installer/tests/unit/mariadb.bats`.

**Interfaces:**
- Consumes: the step 1 CLI `bin/mailhostctl migrate|db:users`. With `DB_HOST` unset, root connects over the unix socket without a password, as `Connection::root` does.
- Produces:
  - `/etc/mailhost/db.env` (0600 root) with `DB_NAME=mailhost` and `DB_PASS_MAIL_RO`, `DB_PASS_MAIL_POLICY`, `DB_PASS_MAIL_APP`, `DB_PASS_MAIL_PORTAL` and `DB_PASS_MAILCTL`, each created once.
  - The shell function `db_env_value KEY`, which reads one key from `db.env`. Tasks 8, 9, 11 and 12 use it.
  - The app at `/opt/mailhost/app`.
  - The database `mailhost` with every migration applied, and the five accounts.

Steps inside `module_mariadb`:
1. `pkg_install mariadb-server php8.3-cli php8.3-mysql composer rsync`.
2. Install `/etc/mysql/mariadb.conf.d/90-mailhost.cnf`: `[mysqld]` with `bind-address = 127.0.0.1`, `skip-name-resolve`, `character-set-server = utf8mb4`, `collation-server = utf8mb4_unicode_ci` and `default-time-zone = '+00:00'`. Restart MariaDB if it changed.
3. Remove anonymous users and the `test` database if present. Root keeps Ubuntu's unix_socket authentication, with no password.
4. Copy the repository's `app/` to `/opt/mailhost/app` with `rsync -a --delete --checksum --itemize-changes --exclude tests/ --exclude vendor/ --exclude phpunit.xml`. Any itemized line counts as changed. Then run `composer dump-autoload --no-dev --classmap-authoritative`; there are no runtime packages, so this works offline.
5. `ensure_secret` for each password, written into `db.env` once.
6. Run `MAILHOST_DB_ENV=/etc/mailhost/db.env php /opt/mailhost/app/bin/mailhostctl migrate`, then `db:users`.

- [ ] **Step 1: Write the failing tests** (stub `mysql`, `php`, `rsync` and `composer`):
  - `db.env is created once and kept on re-run`: sha256 is equal after the second run.
  - `db.env holds five passwords of 48 hex characters and is mode 0600`.
  - `cnf binds to 127.0.0.1 and sets UTC`.
  - `migrate runs before db:users`: checked by order in `$STUB_LOG`.
- [ ] **Step 2: Run them and watch them fail.**
- [ ] **Step 3: Implement it.**
- [ ] **Step 4: Run them and watch them pass, then run shellcheck.**
- [ ] **Step 5: Verify as root after running the module:**
  - Run `mysql -NB -e "SELECT COUNT(*) FROM mailhost.schema_migrations"`. Expected: `14` (or the count of migrations in the repo).
  - As `mail_ro` (defaults file from `db.env`): `SELECT name FROM v_domains` succeeds and `SELECT * FROM mailboxes` fails with error 1142.
  - Run `ss -ltnH 'sport = :3306'`. Expected: 127.0.0.1 only.
  - Run the module again. Expected: no `changed` lines and the same `db.env` hash.
- [ ] **Step 6: Commit.** `git commit -m "feat(installer): MariaDB, app CLI, migrations and DB accounts"`

### Task 6: Redis (`40-redis.sh`)

**Files:** Create `installer/lib/40-redis.sh` and `installer/templates/redis/redis.conf`. Test: `installer/tests/unit/redis.bats`.

**Interfaces:** Produces `module_redis`, `/etc/mailhost/redis.pass` (0640 root:redis, created once), and `/etc/redis/redis.conf` (0640 root:redis, owned completely, decision 7). The config holds:
- `bind 127.0.0.1 -::1`, `port 6379`, `protected-mode yes`, `requirepass <secret>`;
- `supervised auto`, `daemonize yes`, `pidfile /run/redis/redis-server.pid`;
- `logfile /var/log/redis/redis-server.log`, `dir /var/lib/redis`.

Memory limits and eviction come in step 3, for Rspamd.

- [ ] **Step 1: Write the failing tests:**
  - `binds loopback only with protected mode`;
  - `requirepass equals the secret file`;
  - `secret kept on re-run`.
- [ ] **Step 2: Run them and watch them fail.**
- [ ] **Step 3: Implement it.** Restart Redis on a changed config.
- [ ] **Step 4: Run them and watch them pass, then run shellcheck.**
- [ ] **Step 5: Verify:**
  - `REDISCLI_AUTH=$(cat /etc/mailhost/redis.pass) redis-cli ping` returns `PONG`.
  - `redis-cli ping` without a password returns `NOAUTH`.
  - `ss -ltnH 'sport = :6379'` shows loopback only.
- [ ] **Step 6: Commit.** `git commit -m "feat(installer): Redis on localhost with a password"`

### Task 7: Certificates (`05-tls-bootstrap.sh`, `80-nginx.sh`, `85-certbot.sh`)

**Files:** Create those three modules, `installer/templates/nginx/mailhost-acme.conf` and `installer/templates/certbot/mailhost-reload` (the deploy hook). Test: `installer/tests/unit/tls.bats`.

**Interfaces:** Produces `/etc/mailhost/tls/fullchain.pem` and `/etc/mailhost/tls/privkey.pem`. Tasks 8 and 9 read these paths.

- **`05-tls-bootstrap`** runs once. It creates `/etc/mailhost/tls/selfsigned/{fullchain,privkey}.pem` with `openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -days 825 -subj "/CN=$MAIL_HOST" -addext "subjectAltName=DNS:$MAIL_HOST"`; the key is 0600 root. It creates the two symlinks only if they don't exist yet.
- **`80-nginx`** installs nginx and removes the `default` site symlink. It installs `sites-available/mailhost-acme`, enabled by symlink, which listens on port 80 as the default server for `server_name $MAIL_HOST`:
  - `location ^~ /.well-known/acme-challenge/ { root /var/www/acme; default_type text/plain; }`;
  - `location / { return 301 https://$host$request_uri; }`.

  After the swap it runs `nginx -t`; on failure it calls `restore_backup` and dies. The 443 sites come in steps 5 and 7.
- **`85-certbot`** works in production only; in the test profile it logs `skip` and keeps the self-signed pair.
  - It runs `certbot certonly --webroot -w /var/www/acme -d "$MAIL_HOST" --non-interactive --agree-tos -m "$ADMIN_EMAIL" --keep-until-expiring`.
  - It runs `certbot certonly --dns-cloudflare --dns-cloudflare-credentials "$CF_API_TOKEN_FILE" -d "$ADMIN_HOST"` with the same flags. That certificate is used from step 5.
  - It repoints the two symlinks to `/etc/letsencrypt/live/$MAIL_HOST/`.
  - It installs the deploy hook `/etc/letsencrypt/renewal-hooks/deploy/mailhost-reload` (0755), which reloads each of postfix, dovecot and nginx that is active.
  - If the symlinks changed, it reloads postfix, dovecot and nginx now.

- [ ] **Step 1: Write the failing tests** (stub `openssl`, `certbot`, `nginx` and `systemctl`):
  - `bootstrap creates the pair once`: the second run doesn't call `openssl`.
  - `bootstrap never replaces a symlink that already points elsewhere`.
  - `certbot is not called in the test profile`.
  - `certbot uses webroot /var/www/acme and --keep-until-expiring`.
  - `deploy hook reloads only active services`.
  - `nginx failure restores the previous site`.
- [ ] **Step 2: Run them and watch them fail.**
- [ ] **Step 3: Implement the three modules.**
- [ ] **Step 4: Run them and watch them pass, then run shellcheck.**
- [ ] **Step 5: Verify:**
  - `curl -sI -H "Host: $MAIL_HOST" http://127.0.0.1/x` returns `301` to `https://$MAIL_HOST/x`.
  - A file written to `/var/www/acme/.well-known/acme-challenge/probe` is served verbatim.
  - On the VM in production: `certbot certificates` lists both names, which also confirms the Cloudflare plugin works with certbot 2.9.
- [ ] **Step 6: Commit.** `git commit -m "feat(installer): TLS bootstrap, ACME webroot and certbot"`

### Task 8: Postfix and postsrsd (`50-postfix.sh`)

**Files:**
- Create: `installer/lib/50-postfix.sh`, `installer/templates/postfix/main.cf`, `installer/templates/postfix/master.cf`, `installer/templates/postsrsd/default`
- Create: `installer/templates/postfix/sql/{domains,mailboxes,aliases,sender_login,rejected_recipients,hosted_sender,srs_skip}.cf`
- Test: `installer/tests/unit/postfix.bats`

**Interfaces:**
- Consumes: `db_env_value DB_PASS_MAIL_RO`; `MESSAGE_SIZE_BYTES`, which is `settings.max_message_mb` (read as root: ``mysql -NB -e "SELECT value FROM mailhost.settings WHERE `key` = 'max_message_mb'"``) × 1048576; the TLS paths from Task 7; and the Dovecot sockets from Task 9, which are only needed at delivery time: `private/dovecot-lmtp`, `private/auth` and `private/quota-status`.
- Produces `module_postfix`. Each SQL map file (0640 root:postfix) has `hosts = unix:/run/mysqld/mysqld.sock`, `user = mail_ro`, `password = ${DB_PASS_MAIL_RO}`, `dbname = mailhost` and one query:

| File | `query =` |
|---|---|
| `domains.cf` | `SELECT 1 FROM v_domains WHERE name = '%s'` |
| `mailboxes.cf` | `SELECT maildir FROM v_mailboxes WHERE email = '%s'` |
| `aliases.cf` | `SELECT destination FROM v_aliases WHERE source = '%s'` |
| `sender_login.cf` | `SELECT login FROM v_sender_login WHERE sender = '%s'` |
| `rejected_recipients.cf` | `SELECT CONCAT('550 5.2.1 Recipient unavailable (', reason, ')') FROM v_rejected_recipients WHERE email = '%s'` |
| `hosted_sender.cf` | `SELECT 'REJECT 5.7.1 Log in to send mail as this domain' FROM v_domains WHERE name = '%s'` |
| `srs_skip.cf` | `SELECT '%s' FROM v_domains WHERE name = '%d'` |

`main.cf` values (the ones that matter; everything else stays at Postfix 3.8 defaults):
- Identity: `myhostname = ${MAIL_HOST}`, `myorigin = $myhostname`, `mydestination = $myhostname, localhost`, `mynetworks = 127.0.0.0/8 [::1]/128`, `inet_protocols = all`, `smtpd_banner = $myhostname ESMTP`, `disable_vrfy_command = yes`, `smtpd_helo_required = yes`, `biff = no`.
- Local recipients: `alias_maps = hash:/etc/aliases` (with `root: ${ADMIN_EMAIL}`) and `local_recipient_maps = proxy:unix:passwd.byname $alias_maps tcp:127.0.0.1:10002` (decision 4).
- Virtual domains:
  - `virtual_mailbox_domains = proxy:mysql:/etc/postfix/sql/domains.cf`;
  - `virtual_mailbox_maps = proxy:mysql:/etc/postfix/sql/mailboxes.cf`;
  - `virtual_alias_maps = proxy:mysql:/etc/postfix/sql/aliases.cf`;
  - `virtual_transport = lmtp:unix:private/dovecot-lmtp`.
- `message_size_limit = ${MESSAGE_SIZE_BYTES}` (from `settings.max_message_mb`) and `mailbox_size_limit = 0`. `recipient_delimiter` is not set at all.
- TLS: `smtpd_tls_chain_files = /etc/mailhost/tls/privkey.pem, /etc/mailhost/tls/fullchain.pem`, `smtpd_tls_security_level = may`, `smtpd_tls_auth_only = yes`, `smtpd_tls_protocols = >=TLSv1.2`, `smtpd_tls_mandatory_protocols = >=TLSv1.2`, `smtp_tls_security_level = may`, `smtp_tls_CApath = /etc/ssl/certs`, `smtpd_tls_loglevel = 1`.
- SASL: `smtpd_sasl_type = dovecot`, `smtpd_sasl_path = private/auth`, `smtpd_sasl_auth_enable = no` (switched on only for 587 and 465), `smtpd_sender_login_maps = proxy:mysql:/etc/postfix/sql/sender_login.cf`.
- Port 25 restrictions:
  - `smtpd_helo_restrictions = reject_invalid_helo_hostname, reject_non_fqdn_helo_hostname`;
  - `smtpd_sender_restrictions = reject_non_fqdn_sender, check_sender_access proxy:mysql:/etc/postfix/sql/hosted_sender.cf`;
  - `smtpd_relay_restrictions = reject_unauth_destination` (no `permit_mynetworks`, so not even localhost can relay on port 25);
  - `smtpd_recipient_restrictions = reject_non_fqdn_recipient, check_recipient_access proxy:mysql:/etc/postfix/sql/rejected_recipients.cf, reject_unlisted_recipient, check_policy_service unix:private/quota-status`. The rejected-recipients check comes before the unlisted one so suspended mailboxes get the clear reason (spec §5.2).
- `parent_domain_matches_subdomains = debug_peer_list fast_flush_domains mynetworks permit_mx_backup_networks qmqpd_authorized_clients relay_domains`. This is the default without `smtpd_access_maps`, so `hosted_sender.cf` only matches the exact domain (Review Focus 5).
- postscreen: `postscreen_access_list = permit_mynetworks`, `postscreen_dnsbl_sites = zen.spamhaus.org`, `postscreen_dnsbl_action = enforce`, `postscreen_greet_action = enforce`.
- SRS:
  - `sender_canonical_maps = proxy:mysql:/etc/postfix/sql/srs_skip.cf, tcp:127.0.0.1:10001` and `sender_canonical_classes = envelope_sender`;
  - `recipient_canonical_maps = tcp:127.0.0.1:10002` and `recipient_canonical_classes = envelope_recipient, header_recipient`.
- The contents of `/etc/mailhost/local/postfix-main.cf`, if present, are appended last.

`master.cf`:
- Ubuntu's default service lines without `uucp`, `ifmail`, `bsmtp`, `scalemail-backend` and `mailman`. `smtp inet` runs `postscreen` (plus `smtpd pass`, `dnsblog` and `tlsproxy`). Chroot stays at the Ubuntu default (y).
- `submission inet` (587) with these overrides:
  - `syslog_name=postfix/submission`, `smtpd_tls_security_level=encrypt`, `smtpd_sasl_auth_enable=yes`;
  - `smtpd_client_restrictions=permit_sasl_authenticated,reject`;
  - `smtpd_sender_restrictions=reject_non_fqdn_sender,reject_sender_login_mismatch`;
  - `smtpd_relay_restrictions=permit_sasl_authenticated,reject`;
  - `smtpd_recipient_restrictions=reject_non_fqdn_recipient`;
  - `milter_macro_daemon_name=ORIGINATING`.
- `smtps inet` (465): the same overrides, plus `smtpd_tls_wrappermode=yes` and `syslog_name=postfix/smtps`.

`/etc/default/postsrsd`: `SRS_DOMAIN=${MAIL_HOST}`, `SRS_EXCLUDE_DOMAINS=` (empty; `srs_skip.cf` does this job), `SRS_SECRET=/etc/postsrsd.secret` (the package's own secret, kept), `SRS_FORWARD_PORT=10001`, `SRS_REVERSE_PORT=10002`, `SRS_LISTEN_ADDR=127.0.0.1`.

Validation: copy `/etc/postfix` to a staging directory with the candidate files in place. `postconf -c <stage> -n` must print nothing on stderr. After the swap, `postfix check` must exit 0; otherwise call `restore_backup` for every changed file and die. Start Postfix the first time, `svc_reload postfix` afterwards. Restart postsrsd if its file changed.

- [ ] **Step 1: Write the failing tests** (postconf-backed; skip if postfix is absent):
  - `main.cf parses without warnings`;
  - `every mysql map goes through proxy:`: no `mysql:` in `postconf -c <stage> -n` output that isn't preceded by `proxy:`;
  - `recipient_delimiter is empty`: `postconf -c <stage> -h recipient_delimiter`;
  - `port 25: no SASL, relay only via reject_unauth_destination`;
  - `587 and 465 require TLS and SASL`: `postconf -c <stage> -P submission/inet/smtpd_tls_security_level` is `encrypt`, and `smtps/inet/smtpd_tls_wrappermode` is `yes`;
  - `rejected recipients are checked before unlisted recipients`: by order in `smtpd_recipient_restrictions`;
  - `hosted sender check matches exact domains only`: `smtpd_access_maps` is absent from `parent_domain_matches_subdomains`;
  - `sql maps are 0640 root:postfix`.
- [ ] **Step 2: Run them and watch them fail.**
- [ ] **Step 3: Implement the module and templates.**
- [ ] **Step 4: Run them and watch them pass, then run shellcheck.**
- [ ] **Step 5: Verify the maps against the fixture** (`installer/tests/acceptance/fixture.sh up`, from Task 12; write it now if it doesn't exist yet):
  - `postmap -q example.test proxy:mysql:/etc/postfix/sql/domains.cf` returns `1`.
  - `postmap -q bob@example.test proxy:mysql:/etc/postfix/sql/rejected_recipients.cf` returns `550 5.2.1 Recipient unavailable (mailbox_inactive)`.
  - `postmap -q support@example.test proxy:mysql:/etc/postfix/sql/sender_login.cf` returns `alice@example.test`.
- [ ] **Step 6: Commit.** `git commit -m "feat(installer): Postfix with MySQL maps, postscreen and SRS"`

### Task 9: Dovecot core (`60-dovecot.sh`)

**Files:**
- Create: `installer/lib/60-dovecot.sh`, `installer/templates/dovecot/dovecot.conf`
- Create: `installer/templates/dovecot/sql/{app,main,userdb}.conf.ext` (`app` is rendered ten times with `OFFSET` 0–9)
- Test: `installer/tests/unit/dovecot.bats`

**Interfaces:**
- Consumes: `db_env_value DB_PASS_MAIL_RO`, the TLS paths, and `PRIMARY_DOMAIN`.
- Produces: the sockets Postfix uses (`/var/spool/postfix/private/{dovecot-lmtp,auth,quota-status}`), the `vmail` user and group (uid/gid 5000, home `/var/vmail` 0700, shell `/usr/sbin/nologin`), and `/etc/dovecot/mailhost-sql/*.conf.ext` (0640 root:dovecot).

Every SQL file has `driver = mysql`, `connect = host=/run/mysqld/mysqld.sock dbname=mailhost user=mail_ro password=${DB_PASS_MAIL_RO}` and `default_pass_scheme = ARGON2ID`. Queries:
- `app-<k>.conf.ext`: `password_query = SELECT email AS user, password FROM v_app_auth WHERE email = '%u' ORDER BY app_password_id LIMIT 1 OFFSET <k>`.
- `main.conf.ext`: `password_query = SELECT email AS user, password FROM v_auth WHERE email = '%u'`.
- `userdb.conf.ext`:
  - `user_query = SELECT CONCAT('/var/vmail/', maildir) AS home, 5000 AS uid, 5000 AS gid, CONCAT('*:storage=', quota_mb, 'M') AS quota_rule FROM v_mailboxes WHERE email = '%u'`;
  - `iterate_query = SELECT email AS user FROM v_mailboxes`.

`dovecot.conf` values (one file, owned completely, decision 7):
- Protocols and listeners: `protocols = imap lmtp`, `listen = *, ::`. In `service imap-login`, `inet_listener imap { port = 0 }` and `inet_listener imaps { port = 993  ssl = yes }`.
- TLS: `ssl = required`, `ssl_cert = </etc/mailhost/tls/fullchain.pem`, `ssl_key = </etc/mailhost/tls/privkey.pem`, `ssl_min_protocol = TLSv1.2`, `ssl_prefer_server_ciphers = yes`.
- Auth settings: `disable_plaintext_auth = yes`, `auth_mechanisms = plain login`, `auth_username_format = %Lu`, `auth_verbose = yes`, `auth_verbose_passwords = no`, `auth_cache_size = 10M`, `auth_cache_ttl = 1 hour`, `auth_cache_negative_ttl = 0` (so a new app password works at once).
- Passdbs:
  - ten blocks `passdb { driver = sql  args = /etc/dovecot/mailhost-sql/app-<k>.conf.ext  result_success = return-ok  result_failure = continue  result_internalfail = return-fail }`, with k from 0 to 9;
  - then `passdb { driver = sql  args = /etc/dovecot/mailhost-sql/main.conf.ext }`.
  - There is no PAM and no system passdb. A database failure fails closed.
- Userdb: `userdb { driver = sql  args = /etc/dovecot/mailhost-sql/userdb.conf.ext }`.
- Mail store: `mail_location = maildir:~`, `mail_uid = vmail`, `mail_gid = vmail`, `first_valid_uid = 5000`, `last_valid_uid = 5000`.
- `namespace inbox { inbox = yes  separator = / }` with the special-use mailboxes `Drafts`, `Sent`, `Junk` and `Trash`, each `auto = subscribe`.
- Quota: `mail_plugins = quota`, and in `protocol imap`, `mail_plugins = $mail_plugins imap_quota`. In `plugin`:
  - `quota = count:User quota`, `quota_vsizes = yes`;
  - `quota_status_success = DUNNO`, `quota_status_nouser = DUNNO`, `quota_status_overquota = "552 5.2.2 Mailbox is full"`.
- Services:
  - `service quota-status { executable = quota-status -p postfix  unix_listener /var/spool/postfix/private/quota-status { user = postfix  group = postfix  mode = 0660 }  client_limit = 1 }`;
  - `service lmtp { unix_listener /var/spool/postfix/private/dovecot-lmtp { user = postfix  group = postfix  mode = 0600 } }`;
  - `service auth { unix_listener /var/spool/postfix/private/auth { user = postfix  group = postfix  mode = 0660 }  unix_listener auth-userdb { user = vmail  mode = 0600 } }`.
- LMTP: `recipient_delimiter =` and `protocol lmtp { postmaster_address = postmaster@${PRIMARY_DOMAIN} }`.
- `log_path = syslog`.
- `!include_try /etc/mailhost/local/dovecot/*.conf`.

Validation: render the whole tree into a staging directory, then `doveconf -c <stage>/dovecot.conf -n > /dev/null` must exit 0. Swap. Start Dovecot the first time, `doveadm reload` afterwards.

- [ ] **Step 1: Write the failing tests** (doveconf-backed; skip if dovecot is absent):
  - `dovecot.conf passes doveconf`;
  - `no plaintext listener and TLS required`: `doveconf -c … -h protocols` is `imap lmtp`, the imap port is `0`, `ssl` is `required` and `disable_plaintext_auth` is `yes`;
  - `ten app passdbs then v_auth; failure continues; internal failure stops`: `doveconf -n` shows 11 passdb blocks, the last with `main.conf.ext`, and each app block has `result_failure = continue`;
  - `no PAM or passwd passdb`: `driver = pam` and `driver = passwd` each appear 0 times;
  - `recipient_delimiter is empty`;
  - `app sql files differ only in OFFSET 0..9`.
- [ ] **Step 2: Run them and watch them fail.**
- [ ] **Step 3: Implement the module and templates.**
- [ ] **Step 4: Run them and watch them pass, then run shellcheck.**
- [ ] **Step 5: Verify against the fixture** (`doveadm auth test` and `doveadm user`). This is acceptance C14 in Task 12:
  - alice's main password: success.
  - alice's app password: success.
  - After `UPDATE app_passwords SET revoked_at = UTC_TIMESTAMP() …` and `doveadm auth cache flush alice@example.test`, that app password fails.
  - dave's main password fails; dave's app password succeeds.
  - `support@example.test` fails with any password.
  - A new app password for carol works straight away (negative cache 0).
  - alice's 11th live app password (newest id) fails. This documents decision 1.
  - `doveadm user alice@example.test` shows `home /var/vmail/example.test/alice/`, `uid 5000` and `quota_rule *:storage=1024M`.
  - Create the folder `Work/Boss` over IMAP, then try `Projects/2026 Q1.v2`. Record whether Dovecot accepts the `.` in `installer/README.md` under "Folder names" (decision 8).
- [ ] **Step 6: Commit.** `git commit -m "feat(installer): Dovecot with app-password passdbs, LMTP, SASL and quota"`

### Task 10: Pigeonhole, locked down

**Files:** Modify `installer/templates/dovecot/dovecot.conf`. Test: `installer/tests/unit/dovecot.bats` (extend it).

**Interfaces:** Produces the user script location `/var/vmail/<domain>/<user>/sieve/mailhost.sieve`. Step 4's `sieve_compile` job writes it and compiles it with `sievec`. Settings:
- `protocol lmtp { mail_plugins = $mail_plugins sieve }`.
- In `plugin`:
  - `sieve = file:~/sieve/mailhost.sieve` (a single script file, with no ManageSieve-style active symlink), `sieve_user_log = ~/sieve/mailhost.log`;
  - `sieve_extensions = -enotify`, `sieve_max_redirects = 0` (redirect never runs; spec 17.4);
  - `sieve_vacation_send_from_recipient = yes`, `sieve_vacation_min_period = 1d`, `sieve_vacation_default_period = 7d`, `sieve_vacation_max_period = 30d` (these match `vacation_settings.interval_days` 1–30).
- `dovecot-managesieved` is never installed.
- Left for step 3: `sieve_before` (spam to Junk), `sieve_global_extensions = +vnd.dovecot.pipe` for IMAPSieve training, and `non_smtpd_milters`, so vacation replies get DKIM-signed.

- [ ] **Step 1: Write the failing tests:**
  - `sieve plugin only for lmtp`;
  - `enotify disabled and redirects capped at 0`;
  - `vacation periods 1d / 7d / 30d`;
  - `managesieve not configured`: `doveconf -h protocols` has no `sieve`.
- [ ] **Step 2: Run them and watch them fail.**
- [ ] **Step 3: Implement it.**
- [ ] **Step 4: Run them and watch them pass.**
- [ ] **Step 5: Verify (acceptance C18):**
  - `sievec -c /etc/dovecot/dovecot.conf` on a script with `require "enotify";` exits non-zero.
  - It also exits non-zero on a script with `require "vnd.dovecot.pipe";`.
  - It exits 0 on `require ["fileinto","vacation"];`.
  - alice's script `redirect "x@example.net";`: an inbound message lands in her INBOX, and `postqueue -j` has no message to `x@example.net`.
  - alice's vacation script: a message from `someone@example.net` queues one reply with envelope sender `alice@example.test`. A second message from the same sender within the period queues none.
- [ ] **Step 6: Commit.** `git commit -m "feat(installer): Pigeonhole for LMTP with redirect and enotify disabled"`

### Task 11: Shared mailboxes (namespace, ACL files, shared list)

**Files:**
- Create: `installer/bin/mailhost-shared-acl-sync` (installed to `/usr/local/sbin/`), `installer/templates/dovecot/sql/dict-acl.conf.ext`, `installer/templates/systemd/mailhost-shared-acl-sync.{service,timer}`
- Modify: `installer/templates/dovecot/dovecot.conf`, `installer/lib/60-dovecot.sh`
- Test: `installer/tests/unit/shared_acl.bats`

**Interfaces:**
- Produces `mailhost-shared-acl-sync [--vmail-root DIR]`:
  - It reads, as root over the socket, the rows (`shared_maildir`, `member_login`, `rights`) from `v_shared_acl`, plus every `kind = 'shared'` mailbox's maildir from `mailboxes` (so a shared mailbox with no members gets its files emptied).
  - For each shared Maildir root and each `.Folder` directory in it, it writes `dovecot-acl` (owner vmail, 0600) with one line `user=<member_login> <rights>` per member, sorted. It writes atomically and only if the content changed.
  - It refuses a maildir that doesn't match `^[a-z0-9.-]+/[a-z0-9._+-]+/$`.
  - It exits 0 and prints `changed <path>` for each file written.
  - The pure core is the function `acl_sync_from_rows VMAIL_ROOT`, which reads tab-separated rows on stdin. That's what the bats tests drive.
- Produces a systemd timer that runs it every minute (`OnCalendar=minutely`). Without systemd, the acceptance script calls it directly. Step 4 also calls it after any `shared_access`, `kind` or `status` change.

Dovecot additions:
- `mail_plugins = $mail_plugins acl`, and in `protocol imap`, `mail_plugins = $mail_plugins imap_acl`.
- `namespace shared { type = shared  separator = /  prefix = shared/%%u/  location = maildir:%%h:INDEXPVT=~/shared/%%u  subscriptions = no  list = children }`.
- In `plugin`: `acl = vfile`, `acl_shared_dict = proxy::acl`, `acl_cache_secs = 30`.
- `dict { acl = mysql:/etc/dovecot/mailhost-sql/dict-acl.conf.ext }`. Its map is: `pattern = shared/shared-boxes/user/$to/$from`, `table = v_shared_acl`, `value_field = rights`, `fields { member_login = $to  shared_email = $from }`.
- `service dict { unix_listener dict { user = vmail  group = vmail  mode = 0660 } }`.
- The dict is read-only for us: members have no `a` right and the owner never logs in, so Dovecot never writes to it.

- [ ] **Step 1: Write the failing tests** (temp directory as the vmail root):
  - `writes INBOX and every subfolder`;
  - `removes a member no longer listed`;
  - `leaves files outside shared maildirs alone`;
  - `second run changes nothing`: no output, and mtimes are the same;
  - `refuses a maildir with .. or a leading /`;
  - `a shared mailbox with no members gets empty acl files`.
- [ ] **Step 2: Run them and watch them fail.**
- [ ] **Step 3: Implement the sync tool, the Dovecot additions and the timer** (installed by `60-dovecot`).
- [ ] **Step 4: Run them and watch them pass, then run shellcheck.**
- [ ] **Step 5: Verify (acceptance C19):**
  - After a sync, alice's IMAP `LIST "" "shared/*"` shows `shared/support@example.test`, and she can `SELECT` and `FETCH 1 FLAGS` there. carol can too.
  - erin@other.test (active, other domain) gets `NO` on `SELECT "shared/support@example.test/INBOX"`.
  - After deleting alice's `shared_access` row, running the sync and waiting 35 s, alice's `SELECT` fails.
  - Send-as: alice submits with envelope and From `support@example.test` and it's accepted. carol gets `553 5.7.1 … not owned by user`.
- [ ] **Step 6: Commit.** `git commit -m "feat(installer): shared mailboxes with ACL files and a live shared list"`

### Task 12: Report, acceptance suite and re-run check

**Files:**
- Create: `installer/lib/99-report.sh`, `installer/tests/acceptance/step2-acceptance.sh`, `installer/tests/acceptance/fixture.sh`
- Test: `installer/tests/unit/report.bats`

**Interfaces:**
- `module_report` writes `/root/mailhost-install-report.txt` (0600). It contains:
  - versions (`postconf -h mail_version`, `dovecot --version`, `mariadb --version`, `redis-server --version`, `unbound -V` first line, `nginx -v`, `certbot --version`);
  - `active` or `inactive` for each of postfix, postsrsd, dovecot, mariadb, redis-server, unbound and nginx;
  - listening TCP sockets (`ss -ltnH`);
  - for each name in `v_domains`: `<domain>. MX 10 ${MAIL_HOST}.`, `<domain>. TXT "v=spf1 mx -all"` and `_dmarc.<domain>. TXT "v=DMARC1; p=quarantine; rua=mailto:dmarc-reports@${PRIMARY_DOMAIN}"`, with the line `DKIM: added in step 3`;
  - `<server IPv4> PTR ${MAIL_HOST}.`.
- `fixture.sh up|down` loads and removes the fixture from the "Testing layers" section above. It also adds:
  - a `forwarding_rules` row from alice to `x@example.net` (`keep_copy = 1`), but only for C16;
  - carol's quota set to 1 MB, but only for C15.

  It prints the generated passwords to `$FIXTURE_ENV` (0600, deleted by `down`).

Acceptance checks. Each prints `PASS C<n>`, `FAIL C<n>: <detail>` or `SKIP C<n>: <reason>`:

| # | Check | Pass when |
|---|---|---|
| C1 | IMAPS login, alice, main password | `a OK` on 993 |
| C2 | Port 143 | connection refused |
| C3 | Port 25 `EHLO` | offers `STARTTLS`, no `AUTH` |
| C4 | Port 587 before TLS | no `AUTH` in `EHLO`; `AUTH PLAIN` gets `530` or `503` |
| C5 | 587 STARTTLS + AUTH, alice → carol@example.test | the message is in carol's `new/` within 10 s |
| C6 | 465 implicit TLS + AUTH, carol → alice | delivered |
| C7 | Port 25 inbound from `someone@example.net` → alice | delivered |
| C8 | Port 25 relay to `x@example.net`, no AUTH | `554 5.7.1` Relay access denied |
| C9 | Unknown recipient | `550 5.1.1` |
| C10 | Suspended bob | `550 5.2.1 Recipient unavailable (mailbox_inactive)` |
| C11 | Port 25, `MAIL FROM:<x@example.test>`, no AUTH | `554 5.7.1 Log in to send mail as this domain` |
| C12 | Port 25, `MAIL FROM:<bounce@news.example.test>` → alice | accepted (Review Focus 5) |
| C13 | alice AUTH, `MAIL FROM:<carol@example.test>` | `553 5.7.1` sender not owned |
| C14 | App passwords on IMAP and SMTP (Task 9 cases) | as listed in Task 9 Step 5 |
| C15 | carol over quota (1 MB quota, 2 MB file, `doveadm quota recalc`) | `552 5.2.2 Mailbox is full` at RCPT |
| C16 | SRS: inbound `someone@example.net` → alice, forwarded | the queued copy to `x@example.net` has sender `SRS0=…@${MAIL_HOST}`; alice's own send to `x@example.net` keeps `alice@example.test` |
| C17 | SRS bounce | RCPT to the C16 SRS address gets `250`; forged `SRS0=AAAA=tt=example.net=x@${MAIL_HOST}` gets `550` |
| C18 | Sieve lockdown | as listed in Task 10 Step 5 |
| C19 | Shared mailbox | as listed in Task 11 Step 5 |
| C20 | Certificate on 993, 465 and 587 | the subjectAltName has `${MAIL_HOST}` |
| C21 | Closed ports | nothing on 110, 143, 4190, 11332–11334; 3306 and 6379 only on loopback (`ss -ltnH`) |
| C22 | DNSBL through Unbound (VM) | Task 4 Step 5 |
| C23 | Open relay from another machine (VM) | from the hub, `swaks --server ${MAIL_HOST} --to x@example.net` gets `554` (README has the exact command; the script prints it as SKIP-with-instructions in the workspace) |
| C24 | Re-run | a second `mailhost-install --config …` prints no `changed`, `reloaded` or `restarted`; no new directory under `install-backups/`; the secrets' sha256 values are unchanged |

Mail queued for `example.net` is deferred because there's no route; checks read it with `postqueue -j` and then delete it with `postsuper -d`.

- [ ] **Step 1: Write the failing report tests:**
  - `report lists MX, SPF and DMARC for each domain`;
  - `report contains no secret`: no line matches any value from `db.env` or `redis.pass`;
  - `report is 0600`.
- [ ] **Step 2: Run them and watch them fail.**
- [ ] **Step 3: Implement `99-report.sh`, `fixture.sh` and `step2-acceptance.sh`.**
- [ ] **Step 4: Run the bats tests and watch them pass.** Run `bats installer/tests/unit && shellcheck -x installer/mailhost-install installer/lib/*.sh installer/bin/* installer/tests/acceptance/*.sh`. Expected: all `ok`; shellcheck clean.
- [ ] **Step 5: Full run in the workspace:**
  - Run `installer/mailhost-install --config <test-profile conf>`, then `installer/tests/acceptance/step2-acceptance.sh`.
  - Expected: no `FAIL`; `SKIP` only for C22 and C23 (plus the firewall module's warning).
- [ ] **Step 6: Commit.** `git commit -m "feat(installer): install report and step 2 acceptance suite"`
- [ ] **Step 7: Run on the VM** (by you, or a session linked to the VM). Same commands in the test profile, then C23 from the hub. Expected: no `FAIL` and no `SKIP`.

## Notes for later steps

- **Step 3:** add `milter_default_action = tempfail`, `smtpd_milters` and `non_smtpd_milters` (so vacation replies and other pickup mail get DKIM-signed); `sieve_before` for spam to Junk; `sieve_global_extensions = +vnd.dovecot.pipe` for IMAPSieve; Redis memory policy; fail2ban (Dovecot logs with `auth_verbose = yes`).
- **Step 4:**
  - `doveadm_kick` must also run `doveadm auth cache flush <user>` (Review Focus 3).
  - `mailhost-shared-acl-sync` must run after shared-mailbox changes.
  - `imap_migrate` needs a Dovecot master user and the upstream imapsync.
  - Log ingest reads Dovecot (`auth_verbose`) and Postfix lines from journald.
- **Step 7:** cap live app passwords at 10 (decision 1); check whether `php-sabre-dav` 1.8.12 covers 17.1; use the folder-name finding from Task 9.
