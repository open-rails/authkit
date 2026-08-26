ALTER TABLE profiles.user_providers
  ADD COLUMN IF NOT EXISTS verified_at timestamptz;

UPDATE profiles.user_providers
SET verified_at = created_at
WHERE verified_at IS NULL
  AND COALESCE(profile->>'verification_required', 'false') != 'true';

ALTER TABLE profiles.user_providers
  ALTER COLUMN verified_at SET DEFAULT now();
