-- 0012: new mailctl-deploy job types and settings for the version 1 additions (spec 17.13).
--
-- Job types (the full list is repeated, so this statement is safe to run again):
--   domain_certs   add autoconfig., autodiscover. and mta-sts. names to a domain's certificate;
--   sieve_compile  write and compile one mailbox's Sieve script (rules + out-of-office);
--   spam_lists     write the Rspamd allow/block maps;
--   imap_migrate   copy a mailbox from an old provider (migration_jobs);
--   domain_check   run the health checks of one domain now, for the "check now" button of 17.10
--                  (a small refinement of the list in 17.13).
ALTER TABLE deployments MODIFY COLUMN job_type ENUM(
    'dkim_generate',
    'rspamd_policy',
    'doveadm_kick',
    'quarantine_release',
    'quarantine_delete',
    'domain_archive',
    'mailbox_archive',
    'retention_sweep',
    'domain_certs',
    'sieve_compile',
    'spam_lists',
    'imap_migrate',
    'domain_check'
) NOT NULL;

-- quota_warn_levels      percent thresholds for quota warning emails (17.9);
-- admin_require_2fa      'yes' makes every admin set up an authenticator app (17.5);
-- login_alert_new_country  'yes' emails the user on a first login from a new country (17.6);
-- digest_hour_utc        hour of the daily quarantine digest (17.7);
-- *_retention_days       how long login events, delivery events and DMARC reports are kept.
INSERT IGNORE INTO settings (`key`, value) VALUES
    ('quota_warn_levels', '80,90,95'),
    ('admin_require_2fa', 'no'),
    ('login_alert_new_country', 'yes'),
    ('digest_hour_utc', '6'),
    ('login_events_retention_days', '90'),
    ('delivery_events_retention_days', '30'),
    ('dmarc_retention_days', '180');
