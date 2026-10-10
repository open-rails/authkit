-- parent: 13 sha256:086ec9dc2a8cd734b7b0f8b59fca164f8ab8f538d4dd40433e055f189783a5b0
-- Resource-server mode (#447). A jwks-mode remote application without a
-- jwks_uri has its keys discovered from its issuer's metadata (RFC 8414).
-- role_map maps the role names its tokens carry (RFC 9068 §2.2.3.1) to
-- roles of its group.
SET LOCAL lock_timeout = '10s';

ALTER TABLE remote_applications DROP CONSTRAINT remote_applications_trust_source_xor;
ALTER TABLE remote_applications ADD CONSTRAINT remote_applications_trust_source_xor CHECK (
  (mode = 'jwks' AND public_keys IS NULL)
  OR
  (mode = 'static' AND jwks_uri = '' AND public_keys IS NOT NULL
    AND jsonb_typeof(public_keys) = 'array' AND jsonb_array_length(public_keys) > 0)
);

ALTER TABLE remote_applications ADD COLUMN role_map jsonb
  CONSTRAINT remote_applications_role_map_chk CHECK (role_map IS NULL OR jsonb_typeof(role_map) = 'object');
COMMENT ON COLUMN remote_applications.role_map IS
  'Role names its tokens carry (the roles claim) mapped to role texts of its group; NULL maps none.';

-- A sign-in session bound to a DPoP key (RFC 9449 §5): its access tokens
-- carry cnf.jkt, and each refresh proves the same key.
ALTER TABLE refresh_sessions ADD COLUMN dpop_jkt text
  CONSTRAINT refresh_sessions_dpop_jkt_chk CHECK (dpop_jkt IS NULL OR dpop_jkt ~ '^[A-Za-z0-9_-]{43}$');
COMMENT ON COLUMN refresh_sessions.dpop_jkt IS
  'The RFC 7638 thumbprint of the DPoP key the session is bound to; NULL for a bearer session.';

-- A role in a group held by a trusted issuer's user (its remote_users row),
-- granted by an email invitation the user accepted with that verified
-- address. Its tokens hold the role's permissions there, within their
-- application's role as ever. Deleting the user or the group deletes it.
CREATE TABLE group_remote_user_roles (
  permission_group_id uuid NOT NULL REFERENCES permission_groups(id) ON DELETE CASCADE,
  remote_user_id uuid NOT NULL REFERENCES remote_users(id) ON DELETE CASCADE,
  role text NOT NULL CONSTRAINT grur_role_format_chk CHECK (role ~ '^[a-z][a-z0-9-]*:[a-z][a-z0-9-]*$'),
  invitation_id uuid REFERENCES account_registration_invites(id) ON DELETE SET NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (permission_group_id, remote_user_id)
);
CREATE INDEX group_remote_user_roles_user_idx ON group_remote_user_roles (remote_user_id);
COMMENT ON TABLE group_remote_user_roles IS
  'Roles trusted issuers'' users hold in groups, from accepted email invitations; kept while the user and group are.';
