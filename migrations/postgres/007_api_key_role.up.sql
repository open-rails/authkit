-- Hard-cut of the API-key DIRECT-grant permission plane (#95: unify principals
-- on roles). An API key (profiles.service_tokens) now references exactly ONE org
-- ROLE; its effective permissions are resolved FROM that role at use time, so
-- editing the role updates every key that holds it (the whole point). The
-- bespoke-permissions use case is served by a custom org role. Resource-scope
-- (profiles.service_token_resources) stays a SEPARATE, orthogonal binding.
--
-- This mirrors the remote_application unification (006): a principal derives
-- authority ENTIRELY from org role membership, never a per-principal direct
-- permission list. The profiles.service_token_permissions table (+ index) carried
-- that direct grant and is removed wholesale.

SET lock_timeout = '10s';

-- Add the role column. Existing rows (if any) are point-in-time bootstrap creds;
-- this is a greenfield, single-baseline schema with no production data to carry,
-- so a plain NOT NULL is correct. The (org_id, role) FK mirrors org_memberships /
-- org_invites / org_role_permissions: the referenced role MUST exist in the key's
-- owning org. ON DELETE CASCADE means deleting an org role drops the keys that
-- held it (consistent with the membership/invite tables) — operators must
-- re-point keys before retiring a role.
ALTER TABLE profiles.service_tokens
  ADD COLUMN role text NOT NULL;

ALTER TABLE profiles.service_tokens
  ADD CONSTRAINT service_tokens_role_format_chk CHECK (
    char_length(role) BETWEEN 1 AND 64
    AND role ~ '^[a-zA-Z0-9:_-]+$'
  );

ALTER TABLE profiles.service_tokens
  ADD CONSTRAINT service_tokens_org_role_fk
  FOREIGN KEY (org_id, role) REFERENCES profiles.org_roles(org_id, role) ON DELETE CASCADE;

CREATE INDEX IF NOT EXISTS service_tokens_org_role_idx
  ON profiles.service_tokens (org_id, role);

COMMENT ON COLUMN profiles.service_tokens.role IS
  'The single org role this API key holds. Effective permissions are resolved from the role (org_role_permissions) at use time — edit the role to change every key that holds it. Resource-scope is a separate binding (service_token_resources).';

-- Drop the direct-grant plane.
DROP TABLE IF EXISTS profiles.service_token_permissions;
