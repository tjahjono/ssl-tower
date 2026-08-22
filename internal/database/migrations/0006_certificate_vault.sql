-- Phase 10: unify signing requests and monitored endpoints into a single
-- certificate vault. Endpoint monitoring is retired entirely — a certificate
-- now enters the vault either generated in-app (a CSR that comes back
-- signed, or is self-signed) or uploaded directly (a PEM triplet or a
-- PKCS#12 bundle), and expiry is read from the certificate's own notAfter
-- rather than a live TLS handshake against an endpoint.

ALTER TABLE csrs RENAME TO certificates;

ALTER TABLE certificates
    ADD COLUMN IF NOT EXISTS origin               TEXT     NOT NULL DEFAULT 'generated',
    ADD COLUMN IF NOT EXISTS owner                TEXT     NOT NULL DEFAULT '',
    ADD COLUMN IF NOT EXISTS subject              TEXT     NOT NULL DEFAULT '',
    ADD COLUMN IF NOT EXISTS issuer               TEXT     NOT NULL DEFAULT '',
    ADD COLUMN IF NOT EXISTS signature_algorithm  TEXT     NOT NULL DEFAULT '',
    ADD COLUMN IF NOT EXISTS public_key_algorithm TEXT     NOT NULL DEFAULT '',
    ADD COLUMN IF NOT EXISTS key_size             INTEGER  NOT NULL DEFAULT 0,
    ADD COLUMN IF NOT EXISTS chain_length         INTEGER  NOT NULL DEFAULT 0,
    ADD COLUMN IF NOT EXISTS fingerprint_sha256   TEXT     NOT NULL DEFAULT '',
    ADD COLUMN IF NOT EXISTS last_alert_level     SMALLINT NOT NULL DEFAULT 0;

DO $$ BEGIN
    ALTER TABLE certificates ADD CONSTRAINT certificates_origin_check
        CHECK (origin IN ('generated', 'uploaded'));
EXCEPTION WHEN duplicate_object THEN NULL;
END $$;

-- The CSR generator only ever produced 'rsa' or 'ecdsa', hence the original
-- constraint — but an uploaded certificate can carry any key algorithm this
-- app recognises (or doesn't), so key_algorithm is free text from here on.
ALTER TABLE certificates DROP CONSTRAINT IF EXISTS csrs_key_algorithm_check;

CREATE INDEX IF NOT EXISTS certificates_fingerprint_idx
    ON certificates (fingerprint_sha256) WHERE fingerprint_sha256 <> '';
CREATE INDEX IF NOT EXISTS certificates_origin_idx ON certificates (origin);

-- Endpoint monitoring is retired — every certificate now carries its own
-- expiry, so there is nothing left for a periodic TLS handshake to check.
DROP TABLE IF EXISTS monitor_checks;
DROP TABLE IF EXISTS monitors;
