ALTER TABLE profiles.two_factor_settings
  DROP CONSTRAINT IF EXISTS two_factor_settings_method_check,
  DROP CONSTRAINT IF EXISTS phone_required_for_sms,
  ADD COLUMN IF NOT EXISTS totp_secret bytea,
  ADD COLUMN IF NOT EXISTS last_totp_step bigint,
  ADD CONSTRAINT two_factor_settings_method_check CHECK (method IN ('email', 'sms', 'totp')),
  ADD CONSTRAINT phone_required_for_sms CHECK (
    (method = 'sms' AND phone_number IS NOT NULL) OR method <> 'sms'
  );

COMMENT ON COLUMN profiles.two_factor_settings.method IS 'Preferred 2FA method: email, sms, or totp';
COMMENT ON COLUMN profiles.two_factor_settings.totp_secret IS 'Encrypted TOTP shared secret for authenticator-app 2FA';
COMMENT ON COLUMN profiles.two_factor_settings.last_totp_step IS 'Last accepted TOTP time step, used to reject replay';
