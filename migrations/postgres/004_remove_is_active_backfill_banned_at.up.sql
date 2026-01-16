-- Add explicit ban semantics and remove legacy is_active.
--
-- Target semantics:
-- - banned_at IS NOT NULL => user is banned (reversible)
-- - deleted_at IS NOT NULL => user is soft-deleted
-- - active user => banned_at IS NULL AND deleted_at IS NULL

ALTER TABLE profiles.users
  ADD COLUMN IF NOT EXISTS banned_at timestamptz;

-- Backfill: treat legacy is_active=false as "banned" if not already deleted.
DO $$
BEGIN
  IF EXISTS (
    SELECT 1 FROM information_schema.columns
    WHERE table_schema = 'profiles'
      AND table_name = 'users'
      AND column_name = 'is_active'
  ) THEN
    UPDATE profiles.users
       SET banned_at = COALESCE(banned_at, now()),
           updated_at = now()
     WHERE is_active = false
       AND deleted_at IS NULL
       AND banned_at IS NULL;
  END IF;
END $$;

-- Drop legacy is_active once code is migrated.
ALTER TABLE profiles.users
  DROP COLUMN IF EXISTS is_active;

