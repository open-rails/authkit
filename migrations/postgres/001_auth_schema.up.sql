-- AuthKit Schema for PostgreSQL
-- Handles user authentication, registration, passwords, OAuth, 2FA, and session management
-- All apps use admin super-user, no role management needed

SET lock_timeout = '10s';
SET statement_timeout = '300s';

-- Create citext extension for case-insensitive text in public schema
CREATE EXTENSION IF NOT EXISTS citext WITH SCHEMA public;

CREATE SCHEMA IF NOT EXISTS profiles;

-- Users: Core user accounts
-- Users can register with email, phone, or OAuth
CREATE TABLE IF NOT EXISTS profiles.users (
  id                uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  email             public.citext,
  username          public.citext UNIQUE,
  discord_username  text,
  email_verified    boolean NOT NULL DEFAULT false,
  phone_number      text UNIQUE,
  phone_verified    boolean DEFAULT false,
  is_active         boolean NOT NULL DEFAULT true,
  deleted_at        timestamptz,
  biography         text,
  created_at        timestamptz NOT NULL DEFAULT now(),
  updated_at        timestamptz NOT NULL DEFAULT now(),
  last_login        timestamptz
);

-- Case-insensitive uniqueness via partial unique index on citext
-- Partial index allows multiple NULL emails (e.g., OAuth users with unverified emails)
CREATE UNIQUE INDEX IF NOT EXISTS users_email_uidx ON profiles.users (email) WHERE email IS NOT NULL;

COMMENT ON COLUMN profiles.users.phone_number IS 'E.164 format phone number (e.g., +14155551234)';
COMMENT ON COLUMN profiles.users.phone_verified IS 'Whether the phone number has been verified via SMS code';

-- Passwords: Hashed password storage
CREATE TABLE IF NOT EXISTS profiles.user_passwords (
  user_id             uuid PRIMARY KEY REFERENCES profiles.users(id) ON DELETE CASCADE,
  password_hash       text NOT NULL,
  hash_algo           text NOT NULL DEFAULT 'argon2id',
  hash_params         jsonb,
  password_updated_at timestamptz NOT NULL DEFAULT now()
);

-- External providers: OAuth/OIDC provider linkage
CREATE TABLE IF NOT EXISTS profiles.user_providers (
  id                uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id           uuid NOT NULL REFERENCES profiles.users(id) ON DELETE CASCADE,
  issuer            text NOT NULL,
  provider_slug     text,
  subject           text NOT NULL,
  email_at_provider text,
  profile           jsonb,
  created_at        timestamptz NOT NULL DEFAULT now(),
  UNIQUE (issuer, subject),
  UNIQUE (user_id, issuer)
);
CREATE INDEX IF NOT EXISTS user_providers_user_id_idx ON profiles.user_providers (user_id);


-- Roles: User roles and permissions
CREATE TABLE IF NOT EXISTS profiles.roles (
  id          uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  name        text NOT NULL,
  slug        text NOT NULL UNIQUE,
  description text,
  created_at  timestamptz NOT NULL DEFAULT now(),
  updated_at  timestamptz NOT NULL DEFAULT now(),
  deleted_at  timestamptz
);

CREATE TABLE IF NOT EXISTS profiles.user_roles (
  id         uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id    uuid NOT NULL REFERENCES profiles.users(id) ON DELETE CASCADE,
  role_id    uuid NOT NULL REFERENCES profiles.roles(id) ON DELETE CASCADE,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  UNIQUE (user_id, role_id)
);

-- Refresh sessions: Server-side refresh token sessions
CREATE TABLE IF NOT EXISTS profiles.refresh_sessions (
    id                  uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id             uuid NOT NULL REFERENCES profiles.users(id) ON DELETE CASCADE,
    issuer              text NOT NULL,
    family_id           uuid NOT NULL DEFAULT gen_random_uuid(),
    current_token_hash  bytea NOT NULL,
    previous_token_hash bytea,
    created_at          timestamptz NOT NULL DEFAULT now(),
    last_used_at        timestamptz NOT NULL DEFAULT now(),
    expires_at          timestamptz,
    revoked_at          timestamptz,
    user_agent          text,
    ip_addr             inet
);
CREATE UNIQUE INDEX IF NOT EXISTS refresh_sessions_current_hash_active
    ON profiles.refresh_sessions (current_token_hash)
    WHERE revoked_at IS NULL;
CREATE UNIQUE INDEX IF NOT EXISTS refresh_sessions_prev_hash_active
    ON profiles.refresh_sessions (previous_token_hash)
    WHERE revoked_at IS NULL AND previous_token_hash IS NOT NULL;
CREATE INDEX IF NOT EXISTS refresh_sessions_user_active
    ON profiles.refresh_sessions (user_id, issuer)
    WHERE revoked_at IS NULL;

-- Two-factor authentication settings
CREATE TABLE IF NOT EXISTS profiles.two_factor_settings (
    user_id UUID PRIMARY KEY REFERENCES profiles.users(id) ON DELETE CASCADE,
    enabled BOOLEAN NOT NULL DEFAULT false,
    method VARCHAR(10) NOT NULL DEFAULT 'email' CHECK (method IN ('email', 'sms')),
    phone_number VARCHAR(20), -- E.164 format, required if method='sms'
    backup_codes TEXT[], -- Array of hashed backup codes for account recovery
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    -- Ensure phone_number is provided when method is 'sms'
    CONSTRAINT phone_required_for_sms CHECK (
        (method = 'sms' AND phone_number IS NOT NULL) OR
        (method = 'email')
    )
);
CREATE INDEX IF NOT EXISTS idx_two_factor_settings_enabled ON profiles.two_factor_settings(enabled) WHERE enabled = true;

COMMENT ON TABLE profiles.two_factor_settings IS 'Two-factor authentication settings per user (admin accounts)';
COMMENT ON COLUMN profiles.two_factor_settings.method IS 'Preferred 2FA method: email or sms';
COMMENT ON COLUMN profiles.two_factor_settings.backup_codes IS 'Hashed backup codes for account recovery (10 codes)';
