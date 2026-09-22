-- v1.5: admin-editable operational settings, previously .env-only and
-- requiring a restart to change. A plain key/value table, same shape as
-- site_content (0008_site_content.sql) — deliberately generic rather than
-- one typed column per setting, since the whole point is that this set of
-- keys can grow without a new migration each time.
--
-- APP_ENCRYPTION_KEY is also stored here (key 'app_encryption_key'), but
-- gets very different handling from every other key: rotating it
-- re-encrypts every stored private key across certificates and root_cas,
-- atomically, in the same transaction as the settings row write — see
-- CertificateService.RotateEncryptionKey and CLAUDE.md's locked decision.
CREATE TABLE app_settings (
    key        TEXT PRIMARY KEY,
    value      TEXT NOT NULL DEFAULT '',
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_by TEXT NOT NULL DEFAULT ''
);
