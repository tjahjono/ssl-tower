-- Extended key usage becomes configurable at CSR generation time (server
-- auth, client auth, code signing, etc.) instead of the app always requesting
-- (and self-signing with) a fixed server+client pair. While a certificate is
-- pending, this column holds what was requested; once issued, the service
-- layer overwrites it with whatever the issued leaf actually carries.
ALTER TABLE certificates
    ADD COLUMN IF NOT EXISTS ext_key_usage TEXT[] NOT NULL DEFAULT '{}';
