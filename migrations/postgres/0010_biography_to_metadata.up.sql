-- parent: 9 sha256:bd1d89efef1e795c9fc224c49e3f9155ca9553e37d4d3624b087ec38ac06d090
-- Biography is application profile data, not authentication identity.
UPDATE profiles.users
SET metadata = COALESCE(metadata, '{}'::jsonb) || jsonb_build_object('biography', btrim(biography))
WHERE NULLIF(btrim(biography), '') IS NOT NULL
  AND NOT COALESCE(metadata, '{}'::jsonb) ? 'biography';

ALTER TABLE profiles.users DROP COLUMN biography;
