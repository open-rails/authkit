-- #76: STORED, assigned authority for a JWKS principal (remote_application acting
-- AS ITSELF). Direct permissions granted to a remote_application, mirroring
-- profiles.service_token_permissions: authority is what WE ASSIGNED, never what a
-- self-signed token claims. Roles are already assignable via the polymorphic
-- tenant_memberships (#74); this table adds DIRECT permissions.
--
-- NEW numbered migration (NOT appended to an earlier one): migratekit is
-- name-tracked, so tables added to an already-recorded migration never reach
-- existing DBs (the service_tokens gotcha). Idempotent + transactional.

SET lock_timeout = '10s';
SET statement_timeout = '300s';

CREATE TABLE IF NOT EXISTS profiles.remote_application_permissions (
  remote_application_id uuid NOT NULL REFERENCES profiles.remote_applications(id) ON DELETE CASCADE,
  permission            text NOT NULL,
  created_at            timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (remote_application_id, permission),
  CONSTRAINT rap_permission_format_chk CHECK (
    char_length(permission) BETWEEN 1 AND 256
  )
);
CREATE INDEX IF NOT EXISTS rap_app_idx
  ON profiles.remote_application_permissions (remote_application_id);
COMMENT ON TABLE profiles.remote_application_permissions IS
  'Direct permissions assigned to a remote_application principal (#76): STORED authority for the JWKS self-token, mirroring service_token_permissions. Opaque to AuthKit.';
