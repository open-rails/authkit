ALTER TABLE profiles.users
  ADD COLUMN IF NOT EXISTS preferred_locale text,
  ADD COLUMN IF NOT EXISTS preferred_locale_source text,
  ADD COLUMN IF NOT EXISTS preferred_locale_updated_at timestamptz;

COMMENT ON COLUMN profiles.users.preferred_locale IS 'User communication/auth locale, e.g. en, es, de, ko, zh-CN';
COMMENT ON COLUMN profiles.users.preferred_locale_source IS 'Source of preferred_locale, e.g. registration or explicit';
COMMENT ON COLUMN profiles.users.preferred_locale_updated_at IS 'When preferred_locale was last set';
