-- parent: 7 sha256:727422891155b39f068da9b0c4d81c5fc7863396c867fdffe55fad08f6fe885b
ALTER TABLE profiles.user_providers
  ADD COLUMN IF NOT EXISTS verified_at timestamptz;

UPDATE profiles.user_providers
SET verified_at = created_at
WHERE verified_at IS NULL
  AND COALESCE(profile->>'verification_required', 'false') != 'true';

ALTER TABLE profiles.user_providers
  ALTER COLUMN verified_at SET DEFAULT now();
