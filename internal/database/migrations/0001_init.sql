-- Monitored TLS endpoints.
CREATE TABLE IF NOT EXISTS monitors (
    id         UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    host       TEXT        NOT NULL,
    port       INTEGER     NOT NULL DEFAULT 443 CHECK (port > 0 AND port < 65536),
    label      TEXT        NOT NULL DEFAULT '',
    enabled    BOOLEAN     NOT NULL DEFAULT TRUE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT monitors_host_port_key UNIQUE (host, port)
);

-- One row per TLS handshake performed against a monitor.
CREATE TABLE IF NOT EXISTS monitor_checks (
    id                   UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    monitor_id           UUID        NOT NULL REFERENCES monitors (id) ON DELETE CASCADE,
    checked_at           TIMESTAMPTZ NOT NULL DEFAULT now(),
    status               TEXT        NOT NULL CHECK (status IN ('ok', 'expiring', 'critical', 'expired', 'error')),
    subject              TEXT        NOT NULL DEFAULT '',
    issuer               TEXT        NOT NULL DEFAULT '',
    serial_number        TEXT        NOT NULL DEFAULT '',
    not_before           TIMESTAMPTZ,
    not_after            TIMESTAMPTZ,
    days_remaining       INTEGER,
    dns_names            TEXT[]      NOT NULL DEFAULT '{}',
    signature_algorithm  TEXT        NOT NULL DEFAULT '',
    public_key_algorithm TEXT        NOT NULL DEFAULT '',
    key_size             INTEGER     NOT NULL DEFAULT 0,
    fingerprint_sha256   TEXT        NOT NULL DEFAULT '',
    tls_version          TEXT        NOT NULL DEFAULT '',
    chain_verified       BOOLEAN     NOT NULL DEFAULT FALSE,
    leaf_pem             TEXT        NOT NULL DEFAULT '',
    chain_pem            TEXT        NOT NULL DEFAULT '',
    error_message        TEXT        NOT NULL DEFAULT '',
    latency_ms           INTEGER     NOT NULL DEFAULT 0
);

CREATE INDEX IF NOT EXISTS monitor_checks_monitor_checked_idx
    ON monitor_checks (monitor_id, checked_at DESC);

-- Certificate signing requests plus the key material and issued certificate.
CREATE TABLE IF NOT EXISTS csrs (
    id                    UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    common_name           TEXT        NOT NULL,
    organization          TEXT        NOT NULL DEFAULT '',
    organizational_unit   TEXT        NOT NULL DEFAULT '',
    country               TEXT        NOT NULL DEFAULT '',
    province              TEXT        NOT NULL DEFAULT '',
    locality              TEXT        NOT NULL DEFAULT '',
    email                 TEXT        NOT NULL DEFAULT '',
    dns_names             TEXT[]      NOT NULL DEFAULT '{}',
    ip_addresses          TEXT[]      NOT NULL DEFAULT '{}',
    key_algorithm         TEXT        NOT NULL CHECK (key_algorithm IN ('rsa', 'ecdsa')),
    key_bits              INTEGER     NOT NULL DEFAULT 0,
    key_curve             TEXT        NOT NULL DEFAULT '',
    csr_pem               TEXT        NOT NULL,
    private_key_pem       TEXT        NOT NULL,
    private_key_encrypted BOOLEAN     NOT NULL DEFAULT FALSE,
    certificate_pem       TEXT        NOT NULL DEFAULT '',
    chain_pem             TEXT        NOT NULL DEFAULT '',
    self_signed           BOOLEAN     NOT NULL DEFAULT FALSE,
    not_before            TIMESTAMPTZ,
    not_after             TIMESTAMPTZ,
    status                TEXT        NOT NULL DEFAULT 'pending' CHECK (status IN ('pending', 'issued')),
    notes                 TEXT        NOT NULL DEFAULT '',
    created_at            TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at            TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS csrs_created_at_idx ON csrs (created_at DESC);
CREATE INDEX IF NOT EXISTS csrs_common_name_idx ON csrs (lower(common_name));
