-- Reserved global role slugs
--
-- Global roles live in profiles.roles. Org roles are stored separately in profiles.org_roles.
-- "owner" is reserved for org ownership semantics and must not be used as a global role slug.

SET lock_timeout = '10s';
SET statement_timeout = '300s';

DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1
    FROM pg_constraint c
    JOIN pg_class t ON t.oid = c.conrelid
    JOIN pg_namespace n ON n.oid = t.relnamespace
    WHERE c.conname = 'roles_slug_not_owner_chk'
      AND n.nspname = 'profiles'
      AND t.relname = 'roles'
  ) THEN
    ALTER TABLE profiles.roles
      ADD CONSTRAINT roles_slug_not_owner_chk
      CHECK (lower(slug) <> 'owner');
  END IF;
END $$;

