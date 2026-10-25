-- Legacy rows remain explicitly unclassified until a trusted migration maps them.
ALTER TABLE {{schema}}.notify_items
    ADD COLUMN visibility text NOT NULL DEFAULT '',
    ADD COLUMN app_id text NOT NULL DEFAULT '',
    ADD CONSTRAINT notify_items_visibility_check CHECK (
        (visibility IN ('', 'tenant') AND app_id = '') OR
        (visibility = 'app' AND app_id <> '')
    );
CREATE INDEX notify_items_app_inbox ON {{schema}}.notify_items
    (scope, audience, recipient, visibility, app_id, created_at DESC, id DESC);
