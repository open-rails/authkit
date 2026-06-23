DO $$
BEGIN
  IF EXISTS (
    SELECT 1
    FROM information_schema.columns
    WHERE table_schema = 'profiles'
      AND table_name = 'users'
      AND column_name = 'preferred_locale'
  ) THEN
    ALTER TABLE profiles.users RENAME COLUMN preferred_locale TO preferred_language;
  END IF;

  IF EXISTS (
    SELECT 1
    FROM information_schema.columns
    WHERE table_schema = 'profiles'
      AND table_name = 'users'
      AND column_name = 'preferred_locale_source'
  ) THEN
    ALTER TABLE profiles.users DROP COLUMN preferred_locale_source;
  END IF;

  IF EXISTS (
    SELECT 1
    FROM information_schema.columns
    WHERE table_schema = 'profiles'
      AND table_name = 'users'
      AND column_name = 'preferred_locale_updated_at'
  ) THEN
    ALTER TABLE profiles.users DROP COLUMN preferred_locale_updated_at;
  END IF;

  IF EXISTS (
    SELECT 1
    FROM information_schema.columns
    WHERE table_schema = 'profiles'
      AND table_name = 'users'
      AND column_name = 'preferred_language_source'
  ) THEN
    ALTER TABLE profiles.users DROP COLUMN preferred_language_source;
  END IF;

  IF EXISTS (
    SELECT 1
    FROM information_schema.columns
    WHERE table_schema = 'profiles'
      AND table_name = 'users'
      AND column_name = 'preferred_language_updated_at'
  ) THEN
    ALTER TABLE profiles.users DROP COLUMN preferred_language_updated_at;
  END IF;
END $$;

COMMENT ON COLUMN profiles.users.preferred_language IS 'User communication/auth language, e.g. en, es, de, ko, zh';
