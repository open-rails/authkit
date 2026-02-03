-- Add index to speed provider unlink lookups by user + provider slug.
CREATE INDEX IF NOT EXISTS user_providers_user_id_provider_slug_idx
  ON profiles.user_providers (user_id, provider_slug);
