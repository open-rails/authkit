CREATE TABLE IF NOT EXISTS {{schema}}.notify_items (
    scope text NOT NULL,
    id text NOT NULL,
    audience text NOT NULL CHECK (audience IN ('user', 'operator')),
    recipient text NOT NULL,
    source text NOT NULL,
    source_scope text NOT NULL,
    source_id text NOT NULL,
    kind text NOT NULL,
    data jsonb NOT NULL CHECK (jsonb_typeof(data) = 'object'),
    created_at timestamptz NOT NULL,
    read_at timestamptz,
    status text NOT NULL DEFAULT '' CHECK (status IN ('', 'open', 'resolved', 'dismissed')),
    severity text NOT NULL DEFAULT '',
    resolved_at timestamptz,
    updated_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    revision bigint NOT NULL DEFAULT 1 CHECK (revision > 0),
    PRIMARY KEY (scope, id),
    UNIQUE (scope, audience, recipient, source, source_scope, source_id),
    CHECK ((status IN ('resolved', 'dismissed')) = (resolved_at IS NOT NULL))
);
CREATE INDEX IF NOT EXISTS notify_items_inbox_idx
    ON {{schema}}.notify_items(scope, audience, recipient, created_at DESC, id DESC);
CREATE INDEX IF NOT EXISTS notify_items_unread_idx
    ON {{schema}}.notify_items(scope, audience, recipient, created_at DESC, id DESC)
    WHERE read_at IS NULL;
CREATE TABLE IF NOT EXISTS {{schema}}.notify_recipients (
    scope text NOT NULL,
    audience text NOT NULL CHECK (audience IN ('user', 'operator')),
    recipient text NOT NULL,
    erased_at timestamptz,
    PRIMARY KEY (scope, audience, recipient)
);
