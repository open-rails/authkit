-- Tenant RBAC (authkit #46): role -> permission assignments. A role is a NAME
-- (profiles.tenant_roles) plus a set of permission strings. Permissions are OPAQUE
-- to authkit — the embedding app declares its catalog and authkit adds a small
-- base set (tenant:roles:manage, tenant:members:manage, tenant:service_tokens:manage, tenant:read).
-- authkit only stores / serves / validates membership, never meaning.
--
-- Tokens in a role's set: a concrete permission string; `*` = all catalog
-- permissions (the owner role); `!perm` = exclude (lets the app express a
-- default role like admin = `*` minus {tenant:roles:manage, tenant:members:manage}).
CREATE TABLE IF NOT EXISTS profiles.tenant_role_permissions (
  tenant_id     uuid NOT NULL,
  role       text NOT NULL,
  permission text NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  UNIQUE (tenant_id, role, permission),
  FOREIGN KEY (tenant_id, role) REFERENCES profiles.tenant_roles(tenant_id, role) ON DELETE CASCADE,
  CONSTRAINT tenant_role_permissions_perm_len_chk CHECK (char_length(permission) BETWEEN 1 AND 128)
);
CREATE INDEX IF NOT EXISTS tenant_role_permissions_role_idx
  ON profiles.tenant_role_permissions (tenant_id, role);

-- Backfill existing tenants: the owner role grants everything (`*`). New tenants get
-- this (plus any app-declared default roles) seeded at creation in code.
INSERT INTO profiles.tenant_role_permissions (tenant_id, role, permission)
SELECT tenant_id, role, '*' FROM profiles.tenant_roles WHERE role = 'owner'
ON CONFLICT (tenant_id, role, permission) DO NOTHING;
