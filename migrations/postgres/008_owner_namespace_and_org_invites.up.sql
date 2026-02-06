-- Owner-namespace hardening + org invitations

SET lock_timeout = '10s';
SET statement_timeout = '300s';

-- Personal org metadata.
ALTER TABLE profiles.orgs
  ADD COLUMN IF NOT EXISTS is_personal boolean NOT NULL DEFAULT false,
  ADD COLUMN IF NOT EXISTS owner_user_id uuid REFERENCES profiles.users(id) ON DELETE RESTRICT;

-- Personal orgs must have an owner; regular orgs must not.
DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1
    FROM pg_constraint
    WHERE conname = 'orgs_personal_owner_chk'
      AND conrelid = 'profiles.orgs'::regclass
  ) THEN
    ALTER TABLE profiles.orgs
      ADD CONSTRAINT orgs_personal_owner_chk
      CHECK (
        (is_personal = true AND owner_user_id IS NOT NULL)
        OR (is_personal = false AND owner_user_id IS NULL)
      );
  END IF;
END $$;

-- A user can own at most one active personal org.
CREATE UNIQUE INDEX IF NOT EXISTS orgs_owner_user_personal_uidx
  ON profiles.orgs(owner_user_id)
  WHERE is_personal = true AND deleted_at IS NULL;

-- User slug aliases preserve owner-namespace links across username renames.
CREATE TABLE IF NOT EXISTS profiles.user_slug_aliases (
  user_id     uuid NOT NULL REFERENCES profiles.users(id) ON DELETE CASCADE,
  slug        public.citext NOT NULL UNIQUE,
  created_at  timestamptz NOT NULL DEFAULT now(),
  deleted_at  timestamptz,
  PRIMARY KEY (user_id, slug)
);

DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1
    FROM pg_constraint
    WHERE conname = 'user_slug_aliases_slug_format_chk'
      AND conrelid = 'profiles.user_slug_aliases'::regclass
  ) THEN
    ALTER TABLE profiles.user_slug_aliases
      ADD CONSTRAINT user_slug_aliases_slug_format_chk
      CHECK (
        char_length(slug::text) BETWEEN 1 AND 63
        AND slug::text ~ '^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$'
      );
  END IF;
END $$;

CREATE INDEX IF NOT EXISTS user_slug_aliases_user_id_idx
  ON profiles.user_slug_aliases(user_id)
  WHERE deleted_at IS NULL;

-- Org invitations (pending -> accepted/declined/revoked/expired).
CREATE TABLE IF NOT EXISTS profiles.org_invites (
  id          uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  org_id      uuid NOT NULL REFERENCES profiles.orgs(id) ON DELETE CASCADE,
  user_id     uuid NOT NULL REFERENCES profiles.users(id) ON DELETE CASCADE,
  invited_by  uuid NOT NULL REFERENCES profiles.users(id) ON DELETE RESTRICT,
  status      text NOT NULL DEFAULT 'pending',
  expires_at  timestamptz,
  acted_at    timestamptz,
  created_at  timestamptz NOT NULL DEFAULT now(),
  updated_at  timestamptz NOT NULL DEFAULT now(),
  deleted_at  timestamptz
);

DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1
    FROM pg_constraint
    WHERE conname = 'org_invites_status_chk'
      AND conrelid = 'profiles.org_invites'::regclass
  ) THEN
    ALTER TABLE profiles.org_invites
      ADD CONSTRAINT org_invites_status_chk
      CHECK (status IN ('pending', 'accepted', 'declined', 'revoked', 'expired'));
  END IF;
END $$;

CREATE INDEX IF NOT EXISTS org_invites_org_idx ON profiles.org_invites(org_id) WHERE deleted_at IS NULL;
CREATE INDEX IF NOT EXISTS org_invites_user_idx ON profiles.org_invites(user_id) WHERE deleted_at IS NULL;
CREATE INDEX IF NOT EXISTS org_invites_status_idx ON profiles.org_invites(status) WHERE deleted_at IS NULL;

-- Prevent multiple active pending invites for the same org+user pair.
CREATE UNIQUE INDEX IF NOT EXISTS org_invites_pending_org_user_uidx
  ON profiles.org_invites(org_id, user_id)
  WHERE status = 'pending' AND deleted_at IS NULL;
