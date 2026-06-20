-- #95 Layer 2 — Platform RBAC (the Kubernetes ClusterRole analog).
--
-- A COMPLETELY SEPARATE object type from org RBAC: platform roles are assigned
-- to users DIRECTLY (no org, no membership) and grant ONLY `platform:*`
-- permissions — the disjoint directory/entity namespace. The two layers never
-- overlap: a `platform:` perm can ONLY come from a platform role, an `org:` perm
-- ONLY from an org membership (enforced in core/ValidateGrant). A user with no
-- platform_user_roles row has ZERO platform authority, so the regular-user path
-- short-circuits (no second lookup).

SET lock_timeout = '10s';
SET statement_timeout = '300s';

-- platform_roles: the NAMED platform roles (e.g. `super-admin`, `support-desk`,
-- `platform-auditor`). Flat — NOT scoped to any org.
CREATE TABLE IF NOT EXISTS profiles.platform_roles (
  role text PRIMARY KEY,
  created_at timestamptz NOT NULL DEFAULT now(),
  CONSTRAINT platform_roles_role_format_chk CHECK (
    char_length(role) BETWEEN 1 AND 64
    AND role ~ '^[a-zA-Z0-9:_-]+$'
  )
);

-- platform_role_permissions: a platform role's `platform:*` permission tokens
-- (literals + namespace-anchored globs like `platform:*`). The `platform:`-only
-- discipline is enforced at write time in core (ValidateGrant), not by the DB.
CREATE TABLE IF NOT EXISTS profiles.platform_role_permissions (
  role text NOT NULL REFERENCES profiles.platform_roles(role) ON DELETE CASCADE,
  permission text NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  UNIQUE (role, permission),
  CONSTRAINT platform_role_permissions_perm_len_chk CHECK (char_length(permission) BETWEEN 1 AND 128)
);
CREATE INDEX IF NOT EXISTS platform_role_permissions_role_idx
  ON profiles.platform_role_permissions (role);

-- platform_user_roles: WHO holds a platform role (the platform-admin roster).
-- Assigned to a user DIRECTLY — you cannot get platform power by being added to
-- an org. The (user_id) index makes the per-request resolution a single indexed
-- JOIN.
CREATE TABLE IF NOT EXISTS profiles.platform_user_roles (
  user_id uuid NOT NULL REFERENCES profiles.users(id) ON DELETE CASCADE,
  role text NOT NULL REFERENCES profiles.platform_roles(role) ON DELETE CASCADE,
  created_at timestamptz NOT NULL DEFAULT now(),
  UNIQUE (user_id, role)
);
CREATE INDEX IF NOT EXISTS platform_user_roles_user_idx
  ON profiles.platform_user_roles (user_id);

COMMENT ON TABLE profiles.platform_roles IS
  'Layer-2 platform RBAC (#95): named platform roles, assigned to users directly, granting ONLY platform: perms. The disjoint ClusterRole plane — never reaches inside an org.';
