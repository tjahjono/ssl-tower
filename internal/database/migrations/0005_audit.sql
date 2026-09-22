-- The admin-facing audit trail: every login, account change, monitor
-- mutation, CSR mutation, and private-key download. Actor fields are
-- denormalized (captured at write time, not joined from users) so a record
-- stays readable even after the account is deleted.
CREATE TABLE IF NOT EXISTS audit_log (
    id          UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    actor_id    UUID        REFERENCES users (id) ON DELETE SET NULL,
    actor_email TEXT        NOT NULL DEFAULT '',
    action      TEXT        NOT NULL,
    target_type TEXT        NOT NULL DEFAULT '',
    target_id   TEXT        NOT NULL DEFAULT '',
    detail      TEXT        NOT NULL DEFAULT '',
    ip          TEXT        NOT NULL DEFAULT '',
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS audit_log_created_at_idx ON audit_log (created_at DESC);
CREATE INDEX IF NOT EXISTS audit_log_action_idx ON audit_log (action);
CREATE INDEX IF NOT EXISTS audit_log_actor_email_idx ON audit_log (actor_email);
