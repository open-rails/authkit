-- #81: RESTORE profiles.delegated_users (un-drops #78). #78 was right that AUTH
-- does not need it (the token is the source of truth; no verify-path read), but
-- downstream APP + BILLING domains DO want a stable FK anchor for the federated
-- end-user. A delegated user is an IDENTITY ("a federated end-user vouched for by
-- issuer X") consumed by BOTH the app and billing, so it lives in the identity
-- service: openrails billing tables + tensorhub public tables both FK ->
-- profiles.delegated_users(id) (same DB per deployment). authkit makes NO auth
-- decision off this table.
--
-- id is uuidv7 (pg18 native, the fleet's universal pk; NO uuidv5). uuidv7 is
-- random and cannot be content-derived, so idempotency rides the UNIQUE
-- (remote_application_id, subject) natural key, NOT a derived id: TouchDelegatedUser
-- mints the id ONCE via INSERT ... ON CONFLICT DO UPDATE ... RETURNING id.
--
-- NEW numbered migration (migratekit is name-tracked). Idempotent: CREATE ... IF
-- NOT EXISTS makes a re-run a no-op.

SET lock_timeout = '10s';
SET statement_timeout = '300s';

CREATE TABLE IF NOT EXISTS profiles.delegated_users (
  id                    uuid PRIMARY KEY DEFAULT uuidv7(),
  remote_application_id uuid NOT NULL REFERENCES profiles.remote_applications(id) ON DELETE CASCADE,
  issuer                text NOT NULL,
  subject               text NOT NULL,  -- the STABLE merchant-supplied uuid, never a username
  first_seen_at         timestamptz NOT NULL DEFAULT now(),
  last_seen_at          timestamptz NOT NULL DEFAULT now(),
  UNIQUE (remote_application_id, subject)
);

CREATE INDEX IF NOT EXISTS delegated_users_issuer_idx
  ON profiles.delegated_users (issuer);

COMMENT ON TABLE profiles.delegated_users IS
  'Cross-domain identity anchor (#81): a federated end-user vouched for by a remote_application (issuer). App + billing tables FK -> id. NOT an auth artifact — auth rides the token only.';
