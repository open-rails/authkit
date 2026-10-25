ALTER TABLE {{schema}}.notify_items
    ADD COLUMN producer_revision bigint NOT NULL DEFAULT 0 CHECK (producer_revision >= 0),
    ADD COLUMN withdrawn boolean NOT NULL DEFAULT false,
    ADD COLUMN producer_hash bytea,
    ADD CONSTRAINT notify_items_producer_state_check CHECK (
        (producer_revision = 0 AND producer_hash IS NULL AND NOT withdrawn) OR
        (producer_revision > 0 AND producer_hash IS NOT NULL AND octet_length(producer_hash) = 32)
    );
CREATE INDEX notify_items_visible_inbox_idx
    ON {{schema}}.notify_items(scope, audience, recipient, created_at DESC, id DESC)
    WHERE NOT withdrawn AND dismissed_at IS NULL;
