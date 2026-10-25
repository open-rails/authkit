ALTER TABLE {{schema}}.notify_recipients ADD COLUMN IF NOT EXISTS revision bigint NOT NULL DEFAULT 1;
CREATE TABLE IF NOT EXISTS {{schema}}.notify_app_erasures (
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
-- A database guard also covers older publishers that do not know app fences.
-- The real recipient row lock invalidates a pre-erasure repeatable-read view.
CREATE OR REPLACE FUNCTION {{schema}}.notify_guard_app_erasure() RETURNS trigger LANGUAGE plpgsql AS $$
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
DROP TRIGGER IF EXISTS notify_guard_app_erasure ON {{schema}}.notify_items;
CREATE TRIGGER notify_guard_app_erasure BEFORE INSERT ON {{schema}}.notify_items
FOR EACH ROW EXECUTE FUNCTION {{schema}}.notify_guard_app_erasure();
