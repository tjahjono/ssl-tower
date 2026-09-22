-- Tracks the last alert level notified for each monitor, so the alerting
-- service can tell "still critical from last sweep" (no notification) apart
-- from "just became critical" (notify once). 0 means healthy / never alerted.
ALTER TABLE monitors
    ADD COLUMN IF NOT EXISTS last_alert_level SMALLINT NOT NULL DEFAULT 0;
