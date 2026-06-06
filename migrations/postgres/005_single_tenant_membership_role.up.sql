SET lock_timeout = '10s';
SET statement_timeout = '300s';

INSERT INTO profiles.tenant_roles (tenant_id, role)
SELECT DISTINCT tenant_id, 'member'
FROM profiles.tenant_memberships
ON CONFLICT (tenant_id, role) DO NOTHING;

ALTER TABLE profiles.tenant_memberships
  ADD COLUMN IF NOT EXISTS role text NOT NULL DEFAULT 'member';

DO $$
BEGIN
  IF to_regclass('profiles.tenant_membership_roles') IS NOT NULL THEN
    EXECUTE $sql$
      UPDATE profiles.tenant_memberships m
      SET role = COALESCE(
        (
          SELECT r.role
          FROM profiles.tenant_membership_roles r
          WHERE r.tenant_id = m.tenant_id
            AND r.user_id = m.user_id
          ORDER BY (r.role = 'owner') DESC, r.created_at ASC, r.role ASC
          LIMIT 1
        ),
        'member'
      )
    $sql$;
  END IF;
END $$;

ALTER TABLE profiles.tenant_memberships
  DROP CONSTRAINT IF EXISTS tenant_memberships_role_format_chk;

ALTER TABLE profiles.tenant_memberships
  DROP CONSTRAINT IF EXISTS tenant_memberships_role_fk;

ALTER TABLE profiles.tenant_memberships
  DROP CONSTRAINT IF EXISTS tenant_memberships_tenant_id_role_fkey;

ALTER TABLE profiles.tenant_memberships
  ADD CONSTRAINT tenant_memberships_role_format_chk CHECK (
    char_length(role) BETWEEN 1 AND 64
    AND role ~ '^[a-zA-Z0-9:_-]+$'
  ) NOT VALID;

ALTER TABLE profiles.tenant_memberships
  VALIDATE CONSTRAINT tenant_memberships_role_format_chk;

ALTER TABLE profiles.tenant_memberships
  ADD CONSTRAINT tenant_memberships_role_fk
  FOREIGN KEY (tenant_id, role)
  REFERENCES profiles.tenant_roles(tenant_id, role)
  ON DELETE CASCADE;

CREATE INDEX IF NOT EXISTS tenant_memberships_tenant_role_idx
  ON profiles.tenant_memberships (tenant_id, role)
  WHERE deleted_at IS NULL;

DROP TABLE IF EXISTS profiles.tenant_membership_roles;
