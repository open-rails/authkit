-- parent: 12 sha256:fbb0d9e9dd05d03f7b2d57eff79a49776ba3c2e3ba4b5b7d8c8656258c1134e4
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
