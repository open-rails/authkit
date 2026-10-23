-- Coordinated contract migration: stop older writers before applying.
-- Copy committed identity and timestamps verbatim; do not replay old facts.
LOCK TABLE event_log_instance,event_log_scopes,event_log IN ACCESS EXCLUSIVE MODE;
DO $migration$
BEGIN
 EXECUTE replace($helpers$
-- BEGIN helpers/eventlog/postgres schema v1 (verbatim; checked by test)
CREATE TABLE IF NOT EXISTS "__authkit_eventlog_schema__".eventlog_migrations(version integer PRIMARY KEY);
CREATE TABLE "__authkit_eventlog_schema__".eventlog_streams (
 source text NOT NULL, scope text NOT NULL,
 epoch text NOT NULL DEFAULT gen_random_uuid()::text,
 position bigint NOT NULL DEFAULT 0,
 head_id text NOT NULL DEFAULT '',
 pruned_through bigint NOT NULL DEFAULT 0,
 pruned_id text NOT NULL DEFAULT '',
 recorded_at timestamptz NOT NULL DEFAULT '-infinity',
 PRIMARY KEY(source,scope)
);
CREATE TABLE "__authkit_eventlog_schema__".eventlog_events (
 source text NOT NULL, scope text NOT NULL, position bigint NOT NULL,
 id text NOT NULL, boundary text NOT NULL, event_source text NOT NULL, event_type text NOT NULL, version integer NOT NULL,
 occurred_at timestamptz NOT NULL, recorded_at timestamptz NOT NULL,
 subject_type text NOT NULL, subject_id text NOT NULL, data jsonb NOT NULL,
 PRIMARY KEY(source,scope,position), UNIQUE(source,scope,id),
 FOREIGN KEY(source,scope) REFERENCES "__authkit_eventlog_schema__".eventlog_streams(source,scope) ON DELETE CASCADE
);
CREATE INDEX ON "__authkit_eventlog_schema__".eventlog_events(source,scope,event_type,position);
CREATE INDEX ON "__authkit_eventlog_schema__".eventlog_events(source,scope,recorded_at,position);
-- A queue row is part of the mutation transaction and is gone before commit.
-- The identity orders facts inside that transaction, never public cursors.
CREATE TABLE "__authkit_eventlog_schema__".eventlog_pending (
 ordinal bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
 transaction_id xid8 NOT NULL DEFAULT pg_current_xact_id(),
 source text NOT NULL CHECK(source<>''), scope text NOT NULL CHECK(scope<>''),
 id text NOT NULL CHECK(id<>''), boundary text, event_source text NOT NULL, event_type text NOT NULL CHECK(event_type<>''),
 version integer NOT NULL CHECK(version>0), occurred_at timestamptz NOT NULL,
 subject_type text NOT NULL DEFAULT '', subject_id text NOT NULL DEFAULT '', data jsonb NOT NULL
);
CREATE INDEX ON "__authkit_eventlog_schema__".eventlog_pending(transaction_id);
CREATE FUNCTION "__authkit_eventlog_schema__".eventlog_flush() RETURNS trigger LANGUAGE plpgsql SET search_path TO pg_catalog,pg_temp AS $fn$
DECLARE
 s record; e record; next_position bigint; stamp timestamptz;
BEGIN
 -- Every scope touched by this transaction is known before taking any locks.
 FOR s IN SELECT DISTINCT source,scope FROM "__authkit_eventlog_schema__".eventlog_pending
          WHERE transaction_id=pg_current_xact_id() ORDER BY source,scope
 LOOP
  INSERT INTO "__authkit_eventlog_schema__".eventlog_streams(source,scope) VALUES(s.source,s.scope) ON CONFLICT DO NOTHING;
  PERFORM 1 FROM "__authkit_eventlog_schema__".eventlog_streams WHERE source=s.source AND scope=s.scope FOR UPDATE;
 END LOOP;
 FOR e IN SELECT * FROM "__authkit_eventlog_schema__".eventlog_pending WHERE transaction_id=pg_current_xact_id() ORDER BY ordinal
 LOOP
  IF EXISTS(SELECT 1 FROM "__authkit_eventlog_schema__".eventlog_events WHERE source=e.source AND scope=e.scope AND id=e.id) THEN
   IF EXISTS(SELECT 1 FROM "__authkit_eventlog_schema__".eventlog_events WHERE source=e.source AND scope=e.scope AND id=e.id
     AND event_source=e.event_source AND event_type=e.event_type AND version=e.version
     AND occurred_at=e.occurred_at AND subject_type=e.subject_type AND subject_id=e.subject_id AND data=e.data) THEN
    CONTINUE;
   END IF;
   RAISE EXCEPTION 'event ID already records a different fact' USING ERRCODE='23505';
  END IF;
  UPDATE "__authkit_eventlog_schema__".eventlog_streams SET position=position+1,head_id=coalesce(e.boundary,e.id),
   recorded_at=greatest(recorded_at,clock_timestamp())
   WHERE source=e.source AND scope=e.scope RETURNING position,recorded_at INTO next_position,stamp;
  INSERT INTO "__authkit_eventlog_schema__".eventlog_events(source,scope,position,id,boundary,event_source,event_type,version,occurred_at,recorded_at,subject_type,subject_id,data)
   VALUES(e.source,e.scope,next_position,e.id,coalesce(e.boundary,e.id),e.event_source,e.event_type,e.version,e.occurred_at,stamp,e.subject_type,e.subject_id,e.data);
 END LOOP;
 DELETE FROM "__authkit_eventlog_schema__".eventlog_pending WHERE transaction_id=pg_current_xact_id();
 RETURN NULL;
END $fn$;
CREATE CONSTRAINT TRIGGER eventlog_flush_at_commit AFTER INSERT ON "__authkit_eventlog_schema__".eventlog_pending
 DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION "__authkit_eventlog_schema__".eventlog_flush();

CREATE FUNCTION "__authkit_eventlog_schema__".eventlog_immutable() RETURNS trigger LANGUAGE plpgsql SET search_path TO pg_catalog,pg_temp AS $fn$
BEGIN
 RAISE EXCEPTION 'retained event facts are immutable';
END $fn$;
CREATE TRIGGER eventlog_immutable BEFORE UPDATE ON "__authkit_eventlog_schema__".eventlog_events
 FOR EACH ROW EXECUTE FUNCTION "__authkit_eventlog_schema__".eventlog_immutable();

INSERT INTO "__authkit_eventlog_schema__".eventlog_migrations(version) VALUES(1);
-- END helpers/eventlog/postgres schema v1
$helpers$, '"__authkit_eventlog_schema__"', quote_ident(current_schema()));
END
$migration$;

-- Preserve the old deployment-wide epoch for previously issued empty cursors.
-- No stream is created by a read; shared deferred flush applies this default.
DO $epoch$
BEGIN
 EXECUTE format('CREATE FUNCTION %I.event_log_default_epoch() RETURNS text LANGUAGE sql STABLE SET search_path=pg_catalog,pg_temp AS %L',
  current_schema(),format('SELECT epoch::text FROM %I.event_log_instance WHERE singleton',current_schema()));
END
$epoch$;
ALTER TABLE eventlog_streams ALTER COLUMN epoch SET DEFAULT event_log_default_epoch();
CREATE UNIQUE INDEX eventlog_authkit_event_identity ON eventlog_events((id::uuid)) WHERE source='authkit';
CREATE INDEX eventlog_authkit_retention ON eventlog_events(recorded_at,scope,position) WHERE source='authkit';

INSERT INTO eventlog_streams(source,scope,epoch,position,head_id,pruned_through,pruned_id,recorded_at)
 SELECT 'authkit',s.scope,i.epoch::text,s.position,
 coalesce((SELECT event_id::text FROM event_log e WHERE e.scope=s.scope AND e.position=s.position),''),
 s.retained_after,
 coalesce((SELECT event_id::text FROM event_log e WHERE e.scope=s.scope AND e.position=s.retained_after),''),
 coalesce((SELECT max(recorded_at) FROM event_log e WHERE e.scope=s.scope),'-infinity')
 FROM event_log_scopes s CROSS JOIN event_log_instance i WHERE i.singleton;
INSERT INTO eventlog_events(source,scope,position,id,boundary,event_source,event_type,version,
 occurred_at,recorded_at,subject_type,subject_id,data)
 SELECT 'authkit',scope,position,event_id::text,event_id::text,'authkit',kind,
 (payload->>'version')::integer,(payload->>'occurred_at')::timestamptz,recorded_at,
 coalesce(payload->>'subject_kind',''),coalesce(payload->>'subject_id',''),payload FROM event_log;

DROP TABLE event_log;
DROP TABLE event_log_scopes;
-- Existing read SQL stays compatible. Old mutation allocators are retired.
CREATE VIEW event_log AS SELECT scope,position,id::uuid AS event_id,event_type AS kind,
 recorded_at,data AS payload FROM eventlog_events WHERE source='authkit';
CREATE VIEW event_log_scopes AS SELECT scope,position,pruned_through AS retained_after
 FROM eventlog_streams WHERE source='authkit';
