-- #77: Re-anchor remote_application ownership from a CREATOR user to the owning
-- ORG (tenant). owner_user_id becomes creator-audit only (nullable, SET NULL);
-- tenant_id is the durable owner that survives the creator leaving the org.
-- One tenant -> many remote_applications; each issuer belongs to exactly one tenant.
--
-- NEW numbered migration (migratekit is name-tracked). Idempotent + transactional:
-- a no-op on a fresh DB whose 001 baseline already has the final shape.

SET lock_timeout = '10s';
SET statement_timeout = '300s';

ALTER TABLE profiles.remote_applications
  ADD COLUMN IF NOT EXISTS tenant_id uuid REFERENCES profiles.tenants(id);

-- Backfill: tenant_id = the creator's PERSONAL tenant.
UPDATE profiles.remote_applications ra
SET tenant_id = t.id
FROM profiles.tenants t
WHERE ra.tenant_id IS NULL
  AND ra.owner_user_id IS NOT NULL
  AND t.owner_user_id = ra.owner_user_id
  AND t.is_personal = true;

-- Only enforce NOT NULL if every row resolved; else leave nullable + flag for a
-- manual backfill (the table is near-empty pre-prod — never fail the migration).
DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM profiles.remote_applications WHERE tenant_id IS NULL AND deleted_at IS NULL
  ) THEN
    ALTER TABLE profiles.remote_applications ALTER COLUMN tenant_id SET NOT NULL;
  ELSE
    COMMENT ON COLUMN profiles.remote_applications.tenant_id IS
      'Owning tenant. MANUAL BACKFILL NEEDED: some rows had no resolvable personal tenant; set tenant_id then ALTER COLUMN SET NOT NULL.';
  END IF;
END $$;

-- owner_user_id is now creator-audit only: nullable, ON DELETE SET NULL.
ALTER TABLE profiles.remote_applications ALTER COLUMN owner_user_id DROP NOT NULL;
ALTER TABLE profiles.remote_applications DROP CONSTRAINT IF EXISTS remote_applications_owner_user_id_fkey;
ALTER TABLE profiles.remote_applications
  ADD CONSTRAINT remote_applications_owner_user_id_fkey
    FOREIGN KEY (owner_user_id) REFERENCES profiles.users(id) ON DELETE SET NULL;

CREATE INDEX IF NOT EXISTS remote_applications_tenant_idx
  ON profiles.remote_applications (tenant_id);

COMMENT ON COLUMN profiles.remote_applications.owner_user_id IS
  'Creator-audit only (nullable, SET NULL on user delete). Ownership lives in tenant_id.';
