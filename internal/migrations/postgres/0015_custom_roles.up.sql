-- parent: 14 sha256:89a4a0001bfe9bcae294b8899a357491880943a2912a662c8149c0c2b9c26266
-- Custom roles (#448): roles a group defines at run time, held only in that
-- group. Their names (`<persona>:custom-<name>`) never meet a declared role's.
SET LOCAL lock_timeout = '10s';

CREATE TABLE group_custom_roles (
  permission_group_id uuid NOT NULL REFERENCES permission_groups(id) ON DELETE CASCADE,
  role text NOT NULL CONSTRAINT gcr_role_format_chk CHECK (role ~ '^[a-z][a-z0-9-]*:custom-[a-z][a-z0-9-]*$'),
  permissions text[] NOT NULL CONSTRAINT gcr_permissions_chk CHECK (cardinality(permissions) BETWEEN 1 AND 256),
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (permission_group_id, role)
);
COMMENT ON TABLE group_custom_roles IS
  'Roles groups define at run time: what each grants, read live on every check; deleting one first revokes it from every holder.';

-- The role a group-role event names.
ALTER TABLE account_events ADD COLUMN role text NOT NULL DEFAULT '';
