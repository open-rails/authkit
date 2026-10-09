-- parent: 8 sha256:8474d0027d3cc4a9bc395470fc7906321877d3e11097c3388fdda257825ab5be
-- An event names who made the change by its subject, invoker and credential
-- (docs/identity.md); its delivery order is per stream (the user, else the
-- application or group). Undelivered events keep what their old columns
-- told.
SET LOCAL lock_timeout = '10s';

ALTER TABLE account_events RENAME COLUMN subject TO stream;
ALTER INDEX account_events_subject_idx RENAME TO account_events_stream_idx;
ALTER TABLE account_events
  ADD COLUMN subject_kind text NOT NULL DEFAULT '',
  ADD COLUMN subject_id text NOT NULL DEFAULT '',
  ADD COLUMN invoker_issuer text NOT NULL DEFAULT '',
  ADD COLUMN invoker_id text NOT NULL DEFAULT '',
  ADD COLUMN credential_kind text NOT NULL DEFAULT '',
  ADD COLUMN credential_id text NOT NULL DEFAULT '';
UPDATE account_events SET
  subject_kind = CASE actor_kind
    WHEN 'user' THEN 'user' WHEN 'delegated' THEN 'user' WHEN 'remote_application' THEN 'application' ELSE '' END,
  subject_id = CASE WHEN actor_kind IN ('user', 'delegated', 'remote_application') THEN actor_id ELSE '' END,
  invoker_id = CASE WHEN actor_kind IN ('user', 'delegated', 'remote_application') THEN actor_id ELSE '' END,
  credential_kind = CASE actor_kind WHEN 'api_key' THEN 'api_key' WHEN 'system' THEN 'system' ELSE '' END,
  credential_id = CASE WHEN actor_kind = 'api_key' THEN actor_id ELSE '' END
WHERE actor_kind <> '';
ALTER TABLE account_events DROP COLUMN actor_kind, DROP COLUMN actor_id;
COMMENT ON TABLE remote_applications IS
  'Registered applications: external systems that authenticate by signing JWTs verified against configured keys.';
