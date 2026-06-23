CREATE TABLE IF NOT EXISTS profiles.two_factor_factors (
  id uuid PRIMARY KEY DEFAULT uuidv7(),
  user_id uuid NOT NULL REFERENCES profiles.users(id) ON DELETE CASCADE,
  method varchar(10) NOT NULL CHECK (method IN ('email', 'sms', 'totp')),
  phone_number varchar(20),
  totp_secret bytea,
  last_totp_step bigint,
  is_default boolean NOT NULL DEFAULT false,
  enabled boolean NOT NULL DEFAULT true,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  CONSTRAINT two_factor_factor_phone_required_for_sms CHECK (
    (method = 'sms' AND phone_number IS NOT NULL) OR method <> 'sms'
  ),
  CONSTRAINT two_factor_factor_totp_secret_required CHECK (
    (method = 'totp' AND totp_secret IS NOT NULL) OR method <> 'totp'
  )
);

CREATE UNIQUE INDEX IF NOT EXISTS uniq_two_factor_factors_default
  ON profiles.two_factor_factors (user_id)
  WHERE enabled = true AND is_default = true;

CREATE UNIQUE INDEX IF NOT EXISTS uniq_two_factor_factors_user_method
  ON profiles.two_factor_factors (user_id, method)
  WHERE enabled = true;

CREATE INDEX IF NOT EXISTS idx_two_factor_factors_user_enabled
  ON profiles.two_factor_factors (user_id, enabled);

INSERT INTO profiles.two_factor_factors (
  user_id,
  method,
  phone_number,
  totp_secret,
  last_totp_step,
  is_default,
  enabled,
  created_at,
  updated_at
)
SELECT
  user_id,
  method,
  phone_number,
  totp_secret,
  last_totp_step,
  true,
  true,
  created_at,
  updated_at
FROM profiles.two_factor_settings
WHERE enabled = true
ON CONFLICT DO NOTHING;

COMMENT ON TABLE profiles.two_factor_factors IS 'Primary enrolled 2FA factors per user; backup codes remain user-scoped on two_factor_settings';
COMMENT ON COLUMN profiles.two_factor_factors.is_default IS 'Default factor AuthKit challenges first when 2FA is required';
