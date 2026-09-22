-- v1.1: internal certificate authorities. An admin can upload a Root CA
-- (certificate + private key) and then sign a pending CSR with it, instead
-- of only ever self-signing or pasting back a certificate an outside CA
-- issued. Mirrors the certificates table's own private-key storage shape
-- (private_key_pem + private_key_encrypted) so it goes through the exact
-- same Sealer.

CREATE TABLE IF NOT EXISTS root_cas (
    id                    UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    name                  TEXT        NOT NULL,
    certificate_pem       TEXT        NOT NULL,
    private_key_pem       TEXT        NOT NULL,
    private_key_encrypted BOOLEAN     NOT NULL DEFAULT FALSE,
    subject               TEXT        NOT NULL DEFAULT '',
    signature_algorithm   TEXT        NOT NULL DEFAULT '',
    public_key_algorithm  TEXT        NOT NULL DEFAULT '',
    key_size              INTEGER     NOT NULL DEFAULT 0,
    fingerprint_sha256    TEXT        NOT NULL DEFAULT '',
    not_before            TIMESTAMPTZ,
    not_after             TIMESTAMPTZ,
    created_at            TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at            TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT root_cas_name_key UNIQUE (name)
);

CREATE INDEX IF NOT EXISTS root_cas_created_at_idx ON root_cas (created_at DESC);

-- Which Root CA (if any) signed a given certificate — NULL for everything
-- else (self-signed, uploaded/attached from an outside CA, still pending).
-- ON DELETE SET NULL: removing a Root CA record must never invalidate
-- certificates it already signed, since the cryptographic signature lives
-- in the certificate's own PEM regardless of whether this app still has a
-- row for the CA that made it.
ALTER TABLE certificates
    ADD COLUMN IF NOT EXISTS signed_by_root_ca_id UUID REFERENCES root_cas (id) ON DELETE SET NULL;

CREATE INDEX IF NOT EXISTS certificates_signed_by_root_ca_idx
    ON certificates (signed_by_root_ca_id) WHERE signed_by_root_ca_id IS NOT NULL;
