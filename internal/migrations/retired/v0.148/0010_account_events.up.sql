-- parent: 9 sha256:c1ca96944f64c319f2d9fa127c516cc9a6ad9f6cfc3ff7265f2b4eaddb2cb4f7
-- Durable account and group events (Deps.OnEvent). A deployment that sets the
-- hook subscribes its issuer when it binds its River fleet; a change records
-- one row per subscribed issuer in its own transaction, and delivery deletes
-- the row. Rows reference nothing: a purge must not drop its own event.
ALTER TABLE account_delivery_fleets ADD COLUMN events boolean NOT NULL DEFAULT false;

CREATE TABLE account_events (
    id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    issuer text NOT NULL,
    -- Delivery is ordered per subject: the user, else the application or group.
    subject text NOT NULL,
    event_id uuid NOT NULL,
    kind text NOT NULL,
    occurred_at timestamptz NOT NULL DEFAULT now(),
    actor_kind text NOT NULL DEFAULT '',
    actor_id text NOT NULL DEFAULT '',
    user_id uuid,
    group_id uuid,
    persona text NOT NULL DEFAULT '',
    application_id uuid,
    previous_value text NOT NULL DEFAULT '',
    current_value text NOT NULL DEFAULT '',
    reason text NOT NULL DEFAULT '',
    until timestamptz,
    attempts integer NOT NULL DEFAULT 0,
    retry_at timestamptz,
    UNIQUE (event_id, issuer)
);
CREATE INDEX account_events_subject_idx ON account_events (issuer, subject, id);
