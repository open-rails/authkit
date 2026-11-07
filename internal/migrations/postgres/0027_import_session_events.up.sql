ALTER TABLE session_events ADD COLUMN import_id text;

CREATE UNIQUE INDEX session_events_import_id_idx
  ON session_events (user_id, import_id) WHERE import_id IS NOT NULL;
