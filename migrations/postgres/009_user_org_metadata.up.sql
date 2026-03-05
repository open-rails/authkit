-- Add metadata JSONB columns for reserved-account state and future internal flags.
ALTER TABLE profiles.users
  ADD COLUMN IF NOT EXISTS metadata jsonb NOT NULL DEFAULT '{}'::jsonb;

ALTER TABLE profiles.orgs
  ADD COLUMN IF NOT EXISTS metadata jsonb NOT NULL DEFAULT '{}'::jsonb;

COMMENT ON COLUMN profiles.users.metadata IS 'Arbitrary user metadata (internal/admin flags such as reserved)';
COMMENT ON COLUMN profiles.orgs.metadata IS 'Arbitrary org metadata (internal/admin flags such as reserved)';
