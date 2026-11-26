-- The account inbox: receipts per scope and recipient, recipient erasure
-- tombstones and app erasure fences. {{schema}} is the host's schema.
CREATE TABLE {{schema}}.notify_items (
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
    action_requested boolean NOT NULL DEFAULT false,
    source_subject text NOT NULL DEFAULT '',
    dismissed_at timestamptz,
    -- Empty visibility is an unclassified item, never an implicit tenant-wide
    -- grant in an app view.
    visibility text NOT NULL DEFAULT '',
    app_id text NOT NULL DEFAULT '',
    producer_revision bigint NOT NULL DEFAULT 0 CHECK (producer_revision >= 0),
    withdrawn boolean NOT NULL DEFAULT false,
    producer_hash bytea,
    PRIMARY KEY (scope, id),
    UNIQUE (scope, audience, recipient, source, source_scope, source_id),
    CHECK ((status IN ('resolved', 'dismissed')) = (resolved_at IS NOT NULL)),
    CONSTRAINT notify_items_visibility_check CHECK (
        (visibility IN ('', 'tenant') AND app_id = '') OR
        (visibility = 'app' AND app_id <> '')
    ),
    CONSTRAINT notify_items_producer_state_check CHECK (
        (producer_revision = 0 AND producer_hash IS NULL AND NOT withdrawn) OR
        (producer_revision > 0 AND producer_hash IS NOT NULL AND octet_length(producer_hash) = 32)
    )
);
CREATE INDEX notify_items_inbox_idx
    ON {{schema}}.notify_items(scope, audience, recipient, created_at DESC, id DESC);
CREATE INDEX notify_items_unread_idx
    ON {{schema}}.notify_items(scope, audience, recipient, created_at DESC, id DESC)
    WHERE read_at IS NULL;
CREATE INDEX notify_items_active_idx
    ON {{schema}}.notify_items(scope, audience, recipient, created_at DESC, id DESC)
    WHERE dismissed_at IS NULL;
CREATE INDEX notify_items_app_inbox ON {{schema}}.notify_items
    (scope, audience, recipient, visibility, app_id, created_at DESC, id DESC);
CREATE INDEX notify_items_visible_inbox_idx
    ON {{schema}}.notify_items(scope, audience, recipient, created_at DESC, id DESC)
    WHERE NOT withdrawn AND dismissed_at IS NULL;
CREATE TABLE {{schema}}.notify_recipients (
    scope text NOT NULL,
    audience text NOT NULL CHECK (audience IN ('user', 'operator')),
    recipient text NOT NULL,
    erased_at timestamptz,
    revision bigint NOT NULL DEFAULT 1,
    PRIMARY KEY (scope, audience, recipient)
);
CREATE TABLE {{schema}}.notify_app_erasures (
    scope text NOT NULL,
    audience text NOT NULL,
    recipient text NOT NULL,
    app_id text NOT NULL,
    source text NOT NULL,
    source_scope text NOT NULL,
    erased_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY(scope,audience,recipient,app_id,source,source_scope),
    FOREIGN KEY(scope,audience,recipient) REFERENCES {{schema}}.notify_recipients(scope,audience,recipient)
);
-- A database guard also covers publishers that do not know app fences. The
-- real recipient row lock invalidates a pre-erasure repeatable-read view.
CREATE FUNCTION {{schema}}.notify_guard_app_erasure() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    INSERT INTO {{schema}}.notify_recipients(scope,audience,recipient)
    VALUES(NEW.scope,NEW.audience,NEW.recipient) ON CONFLICT DO NOTHING;
    PERFORM 1 FROM {{schema}}.notify_recipients
    WHERE scope=NEW.scope AND audience=NEW.audience AND recipient=NEW.recipient FOR UPDATE;
    IF EXISTS(SELECT 1 FROM {{schema}}.notify_app_erasures f
        WHERE f.scope=NEW.scope AND f.audience=NEW.audience AND f.recipient=NEW.recipient
        AND ((NEW.visibility='app' AND f.app_id<>'' AND NEW.app_id=f.app_id)
          OR (NEW.visibility='' AND f.source<>'' AND NEW.source=f.source AND NEW.source_scope=f.source_scope))) THEN
        RAISE EXCEPTION 'notification app recipient erased' USING ERRCODE='23514';
    END IF;
    RETURN NEW;
END $$;
CREATE TRIGGER notify_guard_app_erasure BEFORE INSERT ON {{schema}}.notify_items
FOR EACH ROW EXECUTE FUNCTION {{schema}}.notify_guard_app_erasure();
