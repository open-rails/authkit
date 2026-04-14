-- Explicit owner-namespace states:
-- - restricted_name: blocked slug with no required login placeholder
-- - parked_org: org exists but platform-held (no required same-slug login)
-- - registered_org: normal org lifecycle

SET lock_timeout = '10s';
SET statement_timeout = '300s';

CREATE TABLE IF NOT EXISTS profiles.owner_reserved_names (
  slug        text PRIMARY KEY,
  created_at  timestamptz NOT NULL DEFAULT now(),
  updated_at  timestamptz NOT NULL DEFAULT now()
);

DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1
    FROM pg_constraint
    WHERE conname = 'owner_reserved_names_slug_format_chk'
      AND conrelid = 'profiles.owner_reserved_names'::regclass
  ) THEN
    ALTER TABLE profiles.owner_reserved_names
      ADD CONSTRAINT owner_reserved_names_slug_format_chk
      CHECK (
        char_length(slug) BETWEEN 1 AND 63
        AND slug ~ '^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$'
      );
  END IF;
END $$;

-- Backfill reserved-name blocklist from legacy reserved metadata.
INSERT INTO profiles.owner_reserved_names (slug)
SELECT lower(u.username::text)
FROM profiles.users u
WHERE u.deleted_at IS NULL
  AND u.username IS NOT NULL
  AND CASE
        WHEN jsonb_typeof(COALESCE(u.metadata, '{}'::jsonb)->'reserved')='boolean'
        THEN (COALESCE(u.metadata, '{}'::jsonb)->>'reserved')::boolean
        ELSE false
      END
ON CONFLICT (slug) DO NOTHING;

INSERT INTO profiles.owner_reserved_names (slug)
SELECT o.slug
FROM profiles.orgs o
WHERE o.deleted_at IS NULL
  AND CASE
        WHEN jsonb_typeof(COALESCE(o.metadata, '{}'::jsonb)->'reserved')='boolean'
        THEN (COALESCE(o.metadata, '{}'::jsonb)->>'reserved')::boolean
        ELSE false
      END
ON CONFLICT (slug) DO NOTHING;

-- Prevent legacy reserved placeholders from becoming loginable.
DELETE FROM profiles.user_passwords p
USING profiles.users u
WHERE p.user_id = u.id
  AND CASE
        WHEN jsonb_typeof(COALESCE(u.metadata, '{}'::jsonb)->'reserved')='boolean'
        THEN (COALESCE(u.metadata, '{}'::jsonb)->>'reserved')::boolean
        ELSE false
      END;

DELETE FROM profiles.user_providers p
USING profiles.users u
WHERE p.user_id = u.id
  AND CASE
        WHEN jsonb_typeof(COALESCE(u.metadata, '{}'::jsonb)->'reserved')='boolean'
        THEN (COALESCE(u.metadata, '{}'::jsonb)->>'reserved')::boolean
        ELSE false
      END;

UPDATE profiles.users u
SET email=NULL,
    email_verified=false,
    phone_number=NULL,
    phone_verified=false,
    updated_at=now()
WHERE CASE
        WHEN jsonb_typeof(COALESCE(u.metadata, '{}'::jsonb)->'reserved')='boolean'
        THEN (COALESCE(u.metadata, '{}'::jsonb)->>'reserved')::boolean
        ELSE false
      END;

-- Auto-convert legacy reserved personal org placeholders into non-personal parked orgs.
UPDATE profiles.orgs o
SET is_personal=false,
    owner_user_id=NULL,
    metadata = jsonb_set(
      jsonb_set(COALESCE(o.metadata, '{}'::jsonb), '{namespace_state}', to_jsonb('parked_org'::text), true),
      '{reserved}', to_jsonb(true), true
    ),
    updated_at=now()
WHERE o.deleted_at IS NULL
  AND o.is_personal=true
  AND CASE
        WHEN jsonb_typeof(COALESCE(o.metadata, '{}'::jsonb)->'reserved')='boolean'
        THEN (COALESCE(o.metadata, '{}'::jsonb)->>'reserved')::boolean
        ELSE false
      END;

-- Backfill explicit org namespace_state for existing rows.
UPDATE profiles.orgs o
SET metadata = jsonb_set(
      COALESCE(o.metadata, '{}'::jsonb),
      '{namespace_state}',
      to_jsonb(
        CASE
          WHEN CASE
                 WHEN jsonb_typeof(COALESCE(o.metadata, '{}'::jsonb)->'reserved')='boolean'
                 THEN (COALESCE(o.metadata, '{}'::jsonb)->>'reserved')::boolean
                 ELSE false
               END
          THEN 'parked_org'::text
          ELSE 'registered_org'::text
        END
      ),
      true
    ),
    updated_at=now()
WHERE o.deleted_at IS NULL
  AND (
    COALESCE(o.metadata, '{}'::jsonb)->>'namespace_state' IS NULL
    OR COALESCE(o.metadata, '{}'::jsonb)->>'namespace_state' = ''
  );
