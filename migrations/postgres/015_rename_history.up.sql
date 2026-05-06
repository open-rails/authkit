-- Rename history audit tables for orgs + users.
--
-- Each rename writes one row: A -> B records from_slug=A and to_slug=B.
-- These rows are the source of truth for historical lookup and old-slug
-- reuse blocking. Replaces the older `*_slug_aliases` tables.
--
-- See e2e/agents/progress.json issue #58 for the full design + query
-- templates. Two lookup indexes per table:
--   (from_slug, renamed_at DESC) — redirect lookup + recent reuse-block seek
--   (owner_id, renamed_at DESC)  — reverse history + rename cooldown check
--
-- No UNIQUE constraint on from_slug: a slug can legitimately appear
-- multiple times across history (rename-back A→B→A→B writes two rows
-- with from_slug=A; or different users at different times after
-- hard-delete). Squat protection comes from the live-row JOIN in
-- `ensureOwnerSlugAvailable`, not a UNIQUE constraint.

SET lock_timeout = '10s';
SET statement_timeout = '300s';

CREATE TABLE IF NOT EXISTS profiles.org_renames (
  id          bigserial PRIMARY KEY,
  org_id      uuid NOT NULL REFERENCES profiles.orgs(id) ON DELETE CASCADE,
  from_slug   text NOT NULL,
  to_slug     text NOT NULL,
  renamed_at  timestamptz NOT NULL DEFAULT now(),
  renamed_by  uuid REFERENCES profiles.users(id) ON DELETE SET NULL,
  CONSTRAINT org_renames_from_slug_format_chk
    CHECK (from_slug = lower(from_slug) AND from_slug ~ '^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$'),
  CONSTRAINT org_renames_to_slug_format_chk
    CHECK (to_slug = lower(to_slug) AND to_slug ~ '^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$')
);

CREATE INDEX IF NOT EXISTS org_renames_from_renamed_idx
  ON profiles.org_renames (from_slug, renamed_at DESC);

CREATE INDEX IF NOT EXISTS org_renames_org_idx
  ON profiles.org_renames (org_id, renamed_at DESC);

CREATE TABLE IF NOT EXISTS profiles.user_renames (
  id          bigserial PRIMARY KEY,
  user_id     uuid NOT NULL REFERENCES profiles.users(id) ON DELETE CASCADE,
  from_slug   text NOT NULL,
  to_slug     text NOT NULL,
  renamed_at  timestamptz NOT NULL DEFAULT now(),
  renamed_by  uuid REFERENCES profiles.users(id) ON DELETE SET NULL,
  CONSTRAINT user_renames_from_slug_format_chk
    CHECK (from_slug = lower(from_slug) AND from_slug ~ '^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$'),
  CONSTRAINT user_renames_to_slug_format_chk
    CHECK (to_slug = lower(to_slug) AND to_slug ~ '^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$')
);

CREATE INDEX IF NOT EXISTS user_renames_from_renamed_idx
  ON profiles.user_renames (from_slug, renamed_at DESC);

CREATE INDEX IF NOT EXISTS user_renames_user_idx
  ON profiles.user_renames (user_id, renamed_at DESC);

-- Backfill from existing alias tables.
--
-- For each org's alias rows ordered by created_at: each alias is one
-- historical from_slug. The to_slug of each alias is the NEXT alias's
-- slug for the same org (or the current orgs.slug for the most recent
-- alias). renamed_at = alias.created_at. renamed_by = NULL (not
-- recoverable from the alias record).
--
-- Implementation note: the rename-history sequence within one org is
-- defined by `created_at` ascending. Use a window function to project
-- each alias's "next" alias (lead) which becomes its to_slug, falling
-- back to the org's current slug for the latest alias.

INSERT INTO profiles.org_renames (org_id, from_slug, to_slug, renamed_at, renamed_by)
SELECT
  a.org_id,
  lower(a.slug)                          AS from_slug,
  lower(COALESCE(
    LEAD(a.slug) OVER (PARTITION BY a.org_id ORDER BY a.created_at),
    o.slug
  ))                                     AS to_slug,
  a.created_at                           AS renamed_at,
  NULL::uuid                             AS renamed_by
FROM   profiles.org_slug_aliases a
JOIN   profiles.orgs o ON o.id = a.org_id
WHERE  a.deleted_at IS NULL
  AND  o.deleted_at IS NULL
ON CONFLICT DO NOTHING;

INSERT INTO profiles.user_renames (user_id, from_slug, to_slug, renamed_at, renamed_by)
SELECT
  a.user_id,
  lower(a.slug::text)                    AS from_slug,
  lower(COALESCE(
    LEAD(a.slug::text) OVER (PARTITION BY a.user_id ORDER BY a.created_at),
    u.username::text
  ))                                     AS to_slug,
  a.created_at                           AS renamed_at,
  NULL::uuid                             AS renamed_by
FROM   profiles.user_slug_aliases a
JOIN   profiles.users u ON u.id = a.user_id
WHERE  a.deleted_at IS NULL
  AND  u.deleted_at IS NULL
ON CONFLICT DO NOTHING;

-- Drop the alias tables. Readers in authkit core (ResolveOrgBySlug,
-- ResolveUserByUsername, ensureOwnerSlugAvailable) and corresponding
-- HTTP handlers must already be flipped over to the renames-table
-- queries before this migration runs in production. The migration
-- runs as one transaction, so partial-rollout (old code reading
-- aliases while migration drops them) is impossible during the
-- migration itself.

DROP TABLE IF EXISTS profiles.org_slug_aliases CASCADE;
DROP TABLE IF EXISTS profiles.user_slug_aliases CASCADE;
