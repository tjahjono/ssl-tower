-- Supports certificate-first monitoring: how many certificates in the presented
-- chain (to flag "no intermediates offered"), and whether the issuer changed
-- since the previous check (a real signal worth surfacing, not just cosmetic).
ALTER TABLE monitor_checks
    ADD COLUMN IF NOT EXISTS chain_length   INTEGER NOT NULL DEFAULT 0,
    ADD COLUMN IF NOT EXISTS issuer_changed BOOLEAN NOT NULL DEFAULT FALSE;

-- Speeds up "does another monitor already track this certificate" lookups,
-- which join monitor_checks back to itself per monitor's latest row.
CREATE INDEX IF NOT EXISTS monitor_checks_fingerprint_idx
    ON monitor_checks (fingerprint_sha256)
    WHERE fingerprint_sha256 <> '';
