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
