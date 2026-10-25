ALTER TABLE {{schema}}.notify_items
    ADD COLUMN source_subject text NOT NULL DEFAULT '',
    ADD COLUMN dismissed_at timestamptz;
CREATE INDEX notify_items_active_idx
    ON {{schema}}.notify_items(scope, audience, recipient, created_at DESC, id DESC)
    WHERE dismissed_at IS NULL;
