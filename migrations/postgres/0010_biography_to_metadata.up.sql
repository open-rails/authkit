-- Biography is application profile data, not authentication identity.
UPDATE profiles.users
SET metadata = COALESCE(metadata, '{}'::jsonb) || jsonb_build_object('biography', btrim(biography))
WHERE NULLIF(btrim(biography), '') IS NOT NULL
  AND NOT COALESCE(metadata, '{}'::jsonb) ? 'biography';

ALTER TABLE profiles.users DROP COLUMN biography;
