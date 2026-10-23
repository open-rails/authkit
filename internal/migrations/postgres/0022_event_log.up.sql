-- One retained record per committed event. Readers own their cursors; no
-- subscription, acknowledgement or delivery state belongs to this log.
CREATE TABLE event_log_instance (
    singleton boolean PRIMARY KEY DEFAULT true CHECK (singleton),
    epoch uuid NOT NULL DEFAULT gen_random_uuid()
);
INSERT INTO event_log_instance DEFAULT VALUES;

CREATE TABLE event_log_scopes (
    scope text PRIMARY KEY,
    position bigint NOT NULL DEFAULT 0 CHECK (position >= 0),
    retained_after bigint NOT NULL DEFAULT 0 CHECK (retained_after >= 0)
);
CREATE TABLE event_log (
    scope text NOT NULL,
    position bigint NOT NULL CHECK (position > 0),
    event_id uuid NOT NULL,
    kind text NOT NULL,
    recorded_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    payload jsonb NOT NULL,
    PRIMARY KEY (scope, position),
    UNIQUE (event_id)
);
CREATE INDEX event_log_retention ON event_log(recorded_at, scope, position);
CREATE INDEX event_log_kind ON event_log(scope, kind, position);

-- Preserve the events which the previous delivery transport still retains.
-- Already delivered/deleted history cannot be reconstructed. Every row here
-- committed before this migration, so this initial ordering cannot skip an
-- in-flight older position. Existing delivery obligations remain separate.
WITH pending AS (
    SELECT DISTINCT ON (event_id) * FROM account_events ORDER BY event_id, id
), numbered AS (
    SELECT *, coalesce(tenant_id::text, 'authority') AS event_scope,
           row_number() OVER (PARTITION BY tenant_id ORDER BY id) AS event_position
    FROM pending
)
INSERT INTO event_log(scope, position, event_id, kind, recorded_at, payload)
SELECT event_scope, event_position, event_id::uuid, kind, occurred_at,
       jsonb_build_object(
           'version', 1, 'id', event_id, 'kind', kind, 'tenant_id', tenant_id,
           'occurred_at', occurred_at, 'subject_kind', subject_kind,
           'subject_id', subject_id, 'invoker_issuer', invoker_issuer,
           'invoker_id', invoker_id, 'credential_kind', credential_kind,
           'credential_id', credential_id, 'user_id', coalesce(user_id::text, ''),
           'group_id', coalesce(group_id::text, ''), 'persona', persona,
           'application_id', coalesce(application_id::text, ''), 'role', role,
           'client_id', client_id, 'agreement', agreement,
           'previous', previous_value, 'current', current_value,
           'reason', reason, 'until', until)
FROM numbered;
INSERT INTO event_log_scopes(scope, position)
SELECT scope, max(position) FROM event_log GROUP BY scope;
