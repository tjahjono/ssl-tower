-- Accounts, sessions, MFA recovery codes, and a login audit trail. Every
-- write route (monitors) and every CSR route is gated behind these.
CREATE TABLE IF NOT EXISTS users (
    id                    UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    email                 TEXT        NOT NULL UNIQUE,
    password_hash         TEXT        NOT NULL,
    role                  TEXT        NOT NULL CHECK (role IN ('admin', 'editor', 'viewer')),
    totp_secret           TEXT        NOT NULL DEFAULT '',
    mfa_enabled           BOOLEAN     NOT NULL DEFAULT FALSE,
    must_change_password  BOOLEAN     NOT NULL DEFAULT FALSE,
    created_at            TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at            TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_login_at         TIMESTAMPTZ
);

-- token_hash (SHA-256 of the opaque cookie value) is the lookup key, so a
-- database leak never exposes a directly usable session token.
CREATE TABLE IF NOT EXISTS sessions (
    token_hash   TEXT        PRIMARY KEY,
    user_id      UUID        NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_seen_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at   TIMESTAMPTZ NOT NULL
);
CREATE INDEX IF NOT EXISTS sessions_user_id_idx ON sessions (user_id);

-- One-time MFA recovery codes, stored hashed like passwords.
CREATE TABLE IF NOT EXISTS recovery_codes (
    id         UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id    UUID        NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    code_hash  TEXT        NOT NULL,
    used_at    TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS recovery_codes_user_id_idx ON recovery_codes (user_id);

-- Every login attempt, successful or not — the raw material for both a
-- simple brute-force guard and the admin-facing audit log in a later phase.
CREATE TABLE IF NOT EXISTS login_attempts (
    id         UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    email      TEXT        NOT NULL,
    ip         TEXT        NOT NULL DEFAULT '',
    success    BOOLEAN     NOT NULL,
    reason     TEXT        NOT NULL DEFAULT '',
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS login_attempts_email_created_idx ON login_attempts (email, created_at DESC);
