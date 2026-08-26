-- v1.2: self-service certificate request tickets. A requester submits a
-- ticket for a new or renewed certificate; an editor/admin approves (and,
-- for an internal ticket, signs in the same action) or rejects it, and for
-- an external ticket fulfills it later by attaching the certificate a
-- public CA issued outside the app. Requesters never touch the certificate
-- vault directly and never download a certificate — see
-- CertificateRequest in internal/domain.

-- Widen the existing role check constraint (originally added unnamed in
-- 0004_auth.sql, so Postgres auto-named it users_role_check) to allow the
-- new requester tier. Drop-then-add is safe to re-run: dropping a
-- constraint that isn't there is a silent no-op in Postgres.
ALTER TABLE users DROP CONSTRAINT IF EXISTS users_role_check;

DO $$ BEGIN
    ALTER TABLE users ADD CONSTRAINT users_role_check
        CHECK (role IN ('admin', 'editor', 'viewer', 'requester'));
EXCEPTION WHEN duplicate_object THEN NULL;
END $$;

CREATE TABLE IF NOT EXISTS certificate_requests (
    id                      UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    requester_id            UUID        NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    requester_email         TEXT        NOT NULL DEFAULT '',

    type                    TEXT        NOT NULL,
    trust_class             TEXT        NOT NULL,
    existing_certificate_id UUID        REFERENCES certificates (id) ON DELETE SET NULL,

    common_name             TEXT        NOT NULL DEFAULT '',
    dns_names               TEXT[]      NOT NULL DEFAULT '{}',
    organization            TEXT        NOT NULL DEFAULT '',
    owner                   TEXT        NOT NULL DEFAULT '',
    justification           TEXT        NOT NULL DEFAULT '',
    po_number               TEXT        NOT NULL DEFAULT '',

    status                  TEXT        NOT NULL DEFAULT 'pending',

    result_certificate_id   UUID        REFERENCES certificates (id) ON DELETE SET NULL,
    root_ca_id              UUID        REFERENCES root_cas (id) ON DELETE SET NULL,

    rejection_reason        TEXT        NOT NULL DEFAULT '',

    approved_by             UUID        REFERENCES users (id) ON DELETE SET NULL,
    approved_at             TIMESTAMPTZ,
    rejected_by             UUID        REFERENCES users (id) ON DELETE SET NULL,
    rejected_at             TIMESTAMPTZ,
    fulfilled_by            UUID        REFERENCES users (id) ON DELETE SET NULL,
    fulfilled_at            TIMESTAMPTZ,
    cancelled_by            UUID        REFERENCES users (id) ON DELETE SET NULL,
    cancelled_at            TIMESTAMPTZ,
    delivered_by            UUID        REFERENCES users (id) ON DELETE SET NULL,
    delivered_at            TIMESTAMPTZ,

    created_at              TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at              TIMESTAMPTZ NOT NULL DEFAULT now()
);

DO $$ BEGIN
    ALTER TABLE certificate_requests ADD CONSTRAINT certificate_requests_type_check
        CHECK (type IN ('new', 'renewal'));
EXCEPTION WHEN duplicate_object THEN NULL;
END $$;

DO $$ BEGIN
    ALTER TABLE certificate_requests ADD CONSTRAINT certificate_requests_trust_class_check
        CHECK (trust_class IN ('internal', 'external'));
EXCEPTION WHEN duplicate_object THEN NULL;
END $$;

DO $$ BEGIN
    ALTER TABLE certificate_requests ADD CONSTRAINT certificate_requests_status_check
        CHECK (status IN ('pending', 'in_progress', 'fulfilled', 'rejected', 'cancelled'));
EXCEPTION WHEN duplicate_object THEN NULL;
END $$;

CREATE INDEX IF NOT EXISTS certificate_requests_status_idx ON certificate_requests (status);
CREATE INDEX IF NOT EXISTS certificate_requests_requester_idx ON certificate_requests (requester_id);
CREATE INDEX IF NOT EXISTS certificate_requests_created_at_idx ON certificate_requests (created_at DESC);
