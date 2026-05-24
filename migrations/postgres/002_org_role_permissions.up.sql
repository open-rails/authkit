-- Org RBAC (authkit #46): role -> permission assignments. A role is a NAME
-- (profiles.org_roles) plus a set of permission strings. Permissions are OPAQUE
-- to authkit — the embedding app declares its catalog and authkit adds a small
-- base set (org:roles:manage, org:members:manage, org:tokens:manage, org:read).
-- authkit only stores / serves / validates membership, never meaning.
--
-- Tokens in a role's set: a concrete permission string; `*` = all catalog
-- permissions (the owner role); `!perm` = exclude (lets the app express a
-- default role like admin = `*` minus {org:roles:manage, org:members:manage}).
CREATE TABLE IF NOT EXISTS profiles.org_role_permissions (
  org_id     uuid NOT NULL,
  role       text NOT NULL,
  permission text NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  UNIQUE (org_id, role, permission),
  FOREIGN KEY (org_id, role) REFERENCES profiles.org_roles(org_id, role) ON DELETE CASCADE,
  CONSTRAINT org_role_permissions_perm_len_chk CHECK (char_length(permission) BETWEEN 1 AND 128)
);
CREATE INDEX IF NOT EXISTS org_role_permissions_role_idx
  ON profiles.org_role_permissions (org_id, role);

-- Backfill existing orgs: the owner role grants everything (`*`). New orgs get
-- this (plus any app-declared default roles) seeded at creation in code.
INSERT INTO profiles.org_role_permissions (org_id, role, permission)
SELECT org_id, role, '*' FROM profiles.org_roles WHERE role = 'owner'
ON CONFLICT (org_id, role, permission) DO NOTHING;
