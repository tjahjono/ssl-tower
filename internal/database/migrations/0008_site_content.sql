-- Admin-editable rich-text blocks for otherwise-static public pages. The
-- Help guide (key 'help') is the first consumer: an admin can rewrite it
-- from the UI instead of it being baked into the binary. No row for a key
-- means "use the built-in default" — see service.DefaultHelpContent.
CREATE TABLE site_content (
    key        TEXT PRIMARY KEY,
    content    TEXT NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_by TEXT NOT NULL DEFAULT ''
);
