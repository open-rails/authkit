-- AuthKit PostgreSQL schema.
-- PostgreSQL 18+ is required for native uuidv7() defaults.

SET lock_timeout = '10s';
SET statement_timeout = '300s';

CREATE EXTENSION IF NOT EXISTS citext WITH SCHEMA public;
CREATE EXTENSION IF NOT EXISTS pgcrypto WITH SCHEMA public;

CREATE SCHEMA IF NOT EXISTS profiles;

-- #125: profiles.uuid_v5() removed (dead — its only caller profiles.role_id was cut).

CREATE TABLE IF NOT EXISTS profiles.bootstrap_applies (
  name text PRIMARY KEY,
  applied_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS profiles.users (
  id uuid PRIMARY KEY DEFAULT uuidv7(),
  email public.citext,
  username public.citext UNIQUE,
  email_verified boolean NOT NULL DEFAULT false,
  phone_number text UNIQUE,
  phone_verified boolean NOT NULL DEFAULT false,
  banned_at timestamptz,
  banned_until timestamptz,
  ban_reason text,
  banned_by uuid REFERENCES profiles.users(id) ON DELETE SET NULL,
  deleted_at timestamptz,
  biography text,
  metadata jsonb NOT NULL DEFAULT '{}'::jsonb,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  last_login timestamptz,
  preferred_language text
);
CREATE UNIQUE INDEX IF NOT EXISTS users_email_uidx
  ON profiles.users (email)
  WHERE email IS NOT NULL;
CREATE INDEX IF NOT EXISTS users_admin_created_idx
  ON profiles.users (created_at DESC, id)
  WHERE deleted_at IS NULL;
CREATE INDEX IF NOT EXISTS users_admin_last_login_idx
  ON profiles.users (last_login DESC, id)
  WHERE deleted_at IS NULL;
CREATE INDEX IF NOT EXISTS users_admin_username_idx
  ON profiles.users (username, id)
  WHERE deleted_at IS NULL;
CREATE INDEX IF NOT EXISTS users_admin_email_idx
  ON profiles.users (email, id)
  WHERE deleted_at IS NULL;
CREATE INDEX IF NOT EXISTS users_deleted_at_idx
  ON profiles.users (deleted_at, id)
  WHERE deleted_at IS NOT NULL;
CREATE INDEX IF NOT EXISTS users_admin_banned_idx
  ON profiles.users (banned_at, id)
  WHERE deleted_at IS NULL AND banned_at IS NOT NULL;
COMMENT ON COLUMN profiles.users.phone_number IS 'E.164 format phone number (e.g. +14155551234)';
COMMENT ON COLUMN profiles.users.phone_verified IS 'Whether the phone number has been verified via SMS code';
COMMENT ON COLUMN profiles.users.banned_at IS 'When the user was banned';
COMMENT ON COLUMN profiles.users.banned_until IS 'When a temporary ban expires (NULL for permanent)';
COMMENT ON COLUMN profiles.users.ban_reason IS 'Reason for ban';
COMMENT ON COLUMN profiles.users.banned_by IS 'User ID of admin who imposed ban';
COMMENT ON COLUMN profiles.users.metadata IS 'Arbitrary user metadata (internal/admin flags such as reserved)';
COMMENT ON COLUMN profiles.users.preferred_language IS 'User communication/auth language, e.g. en, es, de, ko, zh';

CREATE TABLE IF NOT EXISTS profiles.user_passwords (
  user_id uuid PRIMARY KEY REFERENCES profiles.users(id) ON DELETE CASCADE,
  password_hash text NOT NULL,
  hash_algo text NOT NULL DEFAULT 'argon2id',
  hash_params jsonb,
  password_updated_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS profiles.user_providers (
  id uuid PRIMARY KEY DEFAULT uuidv7(),
  user_id uuid NOT NULL REFERENCES profiles.users(id) ON DELETE CASCADE,
  issuer text NOT NULL,
  provider_slug text,
  subject text NOT NULL,
  email_at_provider text,
  profile jsonb,
  created_at timestamptz NOT NULL DEFAULT now(),
  UNIQUE (issuer, subject),
  UNIQUE (user_id, issuer)
);
-- (user_providers_user_id_idx removed: redundant — UNIQUE (user_id, issuer) and
-- the (user_id, provider_slug) index below both already cover user_id-only lookups.)
CREATE INDEX IF NOT EXISTS user_providers_user_id_provider_slug_idx
  ON profiles.user_providers (user_id, provider_slug);

CREATE TABLE IF NOT EXISTS profiles.user_passkey_handles (
  user_id uuid PRIMARY KEY REFERENCES profiles.users(id) ON DELETE CASCADE,
  rpid varchar(512) NOT NULL,
  user_handle bytea NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now()
);
CREATE UNIQUE INDEX IF NOT EXISTS uniq_user_passkey_handles_rpid_user
  ON profiles.user_passkey_handles (rpid, user_id);
CREATE UNIQUE INDEX IF NOT EXISTS uniq_user_passkey_handles_rpid_handle
  ON profiles.user_passkey_handles (rpid, user_handle);

CREATE TABLE IF NOT EXISTS profiles.user_passkeys (
  id uuid PRIMARY KEY DEFAULT uuidv7(),
  user_id uuid NOT NULL REFERENCES profiles.users(id) ON DELETE CASCADE,
  rpid varchar(512) NOT NULL,
  credential_id bytea NOT NULL,
  public_key bytea NOT NULL,
  sign_count bigint NOT NULL DEFAULT 0,
  clone_warning boolean NOT NULL DEFAULT false,
  aaguid bytea,
  transports text[] NOT NULL DEFAULT '{}',
  authenticator_attachment text NOT NULL DEFAULT '',
  backup_eligible boolean NOT NULL DEFAULT false,
  backup_state boolean NOT NULL DEFAULT false,
  user_present boolean NOT NULL DEFAULT false,
  user_verified boolean NOT NULL DEFAULT false,
  flags bytea NOT NULL DEFAULT '\x00',
  attestation_type text NOT NULL DEFAULT '',
  attestation_fmt text NOT NULL DEFAULT '',
  label text,
  created_at timestamptz NOT NULL DEFAULT now(),
  last_used_at timestamptz,
  deleted_at timestamptz
);
CREATE UNIQUE INDEX IF NOT EXISTS uniq_user_passkeys_rpid_credential
  ON profiles.user_passkeys (rpid, credential_id)
  WHERE deleted_at IS NULL;
CREATE INDEX IF NOT EXISTS idx_user_passkeys_user_active
  ON profiles.user_passkeys (user_id)
  WHERE deleted_at IS NULL;

CREATE TABLE IF NOT EXISTS profiles.refresh_sessions (
  id uuid PRIMARY KEY DEFAULT uuidv7(),
  user_id uuid NOT NULL REFERENCES profiles.users(id) ON DELETE CASCADE,
  issuer text NOT NULL,
  family_id uuid NOT NULL DEFAULT uuidv7(),
  current_token_hash bytea NOT NULL,
  previous_token_hash bytea,
  created_at timestamptz NOT NULL DEFAULT now(),
  last_authenticated_at timestamptz,
  last_used_at timestamptz NOT NULL DEFAULT now(),
  expires_at timestamptz,
  revoked_at timestamptz,
  user_agent text,
  ip_addr inet,
  auth_methods text[] NOT NULL DEFAULT ARRAY['pwd']::text[]
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

-- #125: account-level gate + backup codes only. Per-factor data (method/phone/
-- totp_secret/last_totp_step) lives ONLY on mfa_factors.
CREATE TABLE IF NOT EXISTS profiles.mfa_settings (
  user_id uuid PRIMARY KEY REFERENCES profiles.users(id) ON DELETE CASCADE,
  enabled boolean NOT NULL DEFAULT false,
  backup_codes text[],
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now()
);
COMMENT ON TABLE profiles.mfa_settings IS 'Account-level 2FA gate + backup codes per user. enabled=true ⇒ 2FA required at login. Per-factor data lives in mfa_factors.';
COMMENT ON COLUMN profiles.mfa_settings.backup_codes IS 'Hashed backup codes for account recovery';

-- #125: factors are hard-deleted (no per-factor `enabled` flag) — a row
-- existing IS the enabled state.
CREATE TABLE IF NOT EXISTS profiles.mfa_factors (
  id uuid PRIMARY KEY DEFAULT uuidv7(),
  user_id uuid NOT NULL REFERENCES profiles.users(id) ON DELETE CASCADE,
  method varchar(10) NOT NULL CHECK (method IN ('email', 'sms', 'totp')),
  phone_number varchar(20),
  totp_secret bytea,
  last_totp_step bigint,
  is_default boolean NOT NULL DEFAULT false,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  CONSTRAINT mfa_factor_phone_required_for_sms CHECK (
    (method = 'sms' AND phone_number IS NOT NULL) OR method <> 'sms'
  ),
  CONSTRAINT mfa_factor_totp_secret_required CHECK (
    (method = 'totp' AND totp_secret IS NOT NULL) OR method <> 'totp'
  )
);
CREATE UNIQUE INDEX IF NOT EXISTS uniq_mfa_factors_default
  ON profiles.mfa_factors (user_id)
  WHERE is_default = true;
CREATE UNIQUE INDEX IF NOT EXISTS uniq_mfa_factors_user_method
  ON profiles.mfa_factors (user_id, method);
CREATE INDEX IF NOT EXISTS idx_mfa_factors_user
  ON profiles.mfa_factors (user_id);
COMMENT ON TABLE profiles.mfa_factors IS 'Enrolled 2FA factors per user (hard-deleted on removal); backup codes remain user-scoped on mfa_settings';
COMMENT ON COLUMN profiles.mfa_factors.is_default IS 'Default factor AuthKit challenges first when 2FA is required';

CREATE TABLE IF NOT EXISTS profiles.owner_reserved_names (
  slug text PRIMARY KEY,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  CONSTRAINT owner_reserved_names_slug_format_chk CHECK (
    char_length(slug) BETWEEN 1 AND 63
    AND slug ~ '^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$'
  )
);
INSERT INTO profiles.owner_reserved_names (slug)
VALUES ('admin'), ('superuser'), ('root'), ('sudo')
ON CONFLICT (slug) DO NOTHING;

CREATE TABLE IF NOT EXISTS profiles.user_renames (
  id bigserial PRIMARY KEY,
  user_id uuid NOT NULL REFERENCES profiles.users(id) ON DELETE CASCADE,
  from_slug text NOT NULL,
  renamed_at timestamptz NOT NULL DEFAULT now(),
  CONSTRAINT user_renames_from_slug_format_chk CHECK (
    from_slug = lower(from_slug)
    AND from_slug ~ '^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$'
  )
);
CREATE INDEX IF NOT EXISTS user_renames_from_renamed_idx
  ON profiles.user_renames (from_slug, renamed_at DESC);
CREATE INDEX IF NOT EXISTS user_renames_user_idx
  ON profiles.user_renames (user_id, renamed_at DESC);

CREATE TABLE IF NOT EXISTS profiles.group_persona_parents (
  persona text NOT NULL,
  parent_persona text NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (persona),
  CONSTRAINT gpp_persona_format_chk CHECK (persona ~ '^[a-z][a-z0-9-]*$'),
  CONSTRAINT gpp_parent_format_chk CHECK (parent_persona ~ '^[a-z][a-z0-9-]*$'),
  CONSTRAINT gpp_not_self_chk CHECK (persona <> parent_persona),
  CONSTRAINT gpp_root_has_no_parent_chk CHECK (persona <> 'root')
);
COMMENT ON TABLE profiles.group_persona_parents IS
  'Declared containment schema: the single parent persona for each permission-group persona. root is absent.';

CREATE TABLE IF NOT EXISTS profiles.permission_groups (
  id uuid PRIMARY KEY DEFAULT uuidv7(),
  persona text NOT NULL,
  parent_id uuid REFERENCES profiles.permission_groups(id) ON DELETE CASCADE,
  parent_persona text,
  instance_slug text,
  metadata jsonb NOT NULL DEFAULT '{}'::jsonb,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  deleted_at timestamptz,
  CONSTRAINT pg_persona_format_chk CHECK (persona ~ '^[a-z][a-z0-9-]*$'),
  CONSTRAINT pg_instance_slug_format_chk CHECK (
    instance_slug IS NULL OR (
      char_length(instance_slug) BETWEEN 1 AND 63
      AND instance_slug ~ '^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$'
    )
  ),
  CONSTRAINT pg_root_parentless_chk CHECK (
    (persona = 'root' AND parent_id IS NULL AND parent_persona IS NULL AND instance_slug IS NULL)
    OR (persona <> 'root' AND parent_id IS NOT NULL AND parent_persona IS NOT NULL AND instance_slug IS NOT NULL)
  )
);
CREATE UNIQUE INDEX IF NOT EXISTS permission_groups_persona_instance_uidx
  ON profiles.permission_groups (persona, instance_slug)
  WHERE instance_slug IS NOT NULL AND deleted_at IS NULL;
CREATE UNIQUE INDEX IF NOT EXISTS permission_groups_singleton_root_uidx
  ON profiles.permission_groups ((persona = 'root'))
  WHERE persona = 'root' AND deleted_at IS NULL;
CREATE INDEX IF NOT EXISTS permission_groups_parent_idx
  ON profiles.permission_groups (parent_id)
  WHERE parent_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS permission_groups_persona_idx
  ON profiles.permission_groups (persona)
  WHERE deleted_at IS NULL;
COMMENT ON COLUMN profiles.permission_groups.instance_slug IS
  'Lowercase URL-safe slug identifying WHICH instance of the persona (e.g. acme-store for a merchant); the API addressing key. The group id is internal only.';

CREATE OR REPLACE FUNCTION profiles.trg_permission_group_containment() RETURNS trigger
LANGUAGE plpgsql AS $$
DECLARE
  actual_parent_persona text;
BEGIN
  IF NEW.persona = 'root' THEN
    RETURN NEW;
  END IF;

  SELECT persona INTO actual_parent_persona FROM profiles.permission_groups WHERE id = NEW.parent_id;
  IF actual_parent_persona IS NULL THEN
    RAISE EXCEPTION 'permission_groups.parent_id % does not exist', NEW.parent_id
      USING ERRCODE = 'foreign_key_violation';
  END IF;
  IF actual_parent_persona <> NEW.parent_persona THEN
    RAISE EXCEPTION 'permission_groups.parent_persona % does not match parent persona %',
      NEW.parent_persona, actual_parent_persona USING ERRCODE = 'check_violation';
  END IF;
  IF NOT EXISTS (
    SELECT 1 FROM profiles.group_persona_parents
    WHERE persona = NEW.persona AND parent_persona = NEW.parent_persona
  ) THEN
    RAISE EXCEPTION 'a % group may not have a % parent',
      NEW.persona, NEW.parent_persona USING ERRCODE = 'check_violation';
  END IF;
  RETURN NEW;
END;
$$;
CREATE TRIGGER permission_group_containment
  BEFORE INSERT OR UPDATE OF persona, parent_id, parent_persona ON profiles.permission_groups
  FOR EACH ROW EXECUTE FUNCTION profiles.trg_permission_group_containment();

CREATE TABLE IF NOT EXISTS profiles.remote_applications (
  id uuid PRIMARY KEY DEFAULT uuidv7(),
  slug text NOT NULL UNIQUE,
  issuer text NOT NULL UNIQUE,
  jwks_uri text NOT NULL DEFAULT '',
  mode text NOT NULL DEFAULT 'jwks',
  public_keys jsonb,
  enabled boolean NOT NULL DEFAULT true,
  metadata jsonb NOT NULL DEFAULT '{}'::jsonb,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  deleted_at timestamptz,
  -- #125: ON DELETE CASCADE — a remote-app belongs to its group (uniform with api_keys).
  permission_group_id uuid NOT NULL REFERENCES profiles.permission_groups(id) ON DELETE CASCADE,
  CONSTRAINT remote_applications_slug_format_chk CHECK (
    char_length(slug) BETWEEN 1 AND 63
    AND slug ~ '^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$'
  ),
  CONSTRAINT remote_applications_mode_chk CHECK (mode IN ('jwks', 'static')),
  CONSTRAINT remote_applications_trust_source_xor CHECK (
    (mode = 'jwks' AND jwks_uri <> '' AND public_keys IS NULL)
    OR
    (mode = 'static' AND jwks_uri = '' AND public_keys IS NOT NULL
      AND jsonb_typeof(public_keys) = 'array' AND jsonb_array_length(public_keys) > 0)
  )
);
CREATE INDEX IF NOT EXISTS remote_applications_enabled_idx
  ON profiles.remote_applications (enabled)
  WHERE enabled = true;
CREATE INDEX IF NOT EXISTS remote_applications_group_idx
  ON profiles.remote_applications (permission_group_id);
COMMENT ON TABLE profiles.remote_applications IS
  'Federation principals: external systems that authenticate by signing JWTs verified against configured keys.';
COMMENT ON COLUMN profiles.remote_applications.permission_group_id IS
  'Required controlling permission-group. Authority comes from group_remote_application_roles and the parent walk.';

CREATE TABLE IF NOT EXISTS profiles.remote_application_attribute_defs (
  remote_application_id uuid NOT NULL REFERENCES profiles.remote_applications(id) ON DELETE CASCADE,
  key text NOT NULL,
  version integer NOT NULL DEFAULT 1,
  definition jsonb NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (remote_application_id, key, version),
  CONSTRAINT raad_key_format_chk CHECK (
    char_length(key) BETWEEN 1 AND 128
    AND key ~ '^[a-zA-Z0-9:._-]+$'
  ),
  CONSTRAINT raad_version_chk CHECK (version >= 1)
);
CREATE INDEX IF NOT EXISTS raad_app_key_idx
  ON profiles.remote_application_attribute_defs (remote_application_id, key, version DESC);
COMMENT ON TABLE profiles.remote_application_attribute_defs IS
  'Reference-mode attribute definitions: opaque JSON by remote application, key, and version.';

CREATE TABLE IF NOT EXISTS profiles.group_user_roles (
  permission_group_id uuid NOT NULL REFERENCES profiles.permission_groups(id) ON DELETE CASCADE,
  user_id uuid NOT NULL REFERENCES profiles.users(id) ON DELETE CASCADE,
  role text NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  deleted_at timestamptz,
  CONSTRAINT gur_role_format_chk CHECK (role ~ '^[a-z][a-z0-9-]*$')
);
CREATE UNIQUE INDEX IF NOT EXISTS gur_group_user_role_uidx
  ON profiles.group_user_roles (permission_group_id, user_id, role)
  WHERE deleted_at IS NULL;
CREATE INDEX IF NOT EXISTS gur_user_idx
  ON profiles.group_user_roles (user_id)
  WHERE deleted_at IS NULL;
CREATE INDEX IF NOT EXISTS gur_group_idx
  ON profiles.group_user_roles (permission_group_id)
  WHERE deleted_at IS NULL;

CREATE TABLE IF NOT EXISTS profiles.group_remote_application_roles (
  permission_group_id uuid NOT NULL REFERENCES profiles.permission_groups(id) ON DELETE CASCADE,
  remote_application_id uuid NOT NULL REFERENCES profiles.remote_applications(id) ON DELETE CASCADE,
  role text NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  deleted_at timestamptz,
  CONSTRAINT grar_role_format_chk CHECK (role ~ '^[a-z][a-z0-9-]*$')
);
CREATE UNIQUE INDEX IF NOT EXISTS grar_group_remote_application_role_uidx
  ON profiles.group_remote_application_roles (permission_group_id, remote_application_id, role)
  WHERE deleted_at IS NULL;
CREATE INDEX IF NOT EXISTS grar_remote_application_idx
  ON profiles.group_remote_application_roles (remote_application_id)
  WHERE deleted_at IS NULL;
CREATE INDEX IF NOT EXISTS grar_group_idx
  ON profiles.group_remote_application_roles (permission_group_id)
  WHERE deleted_at IS NULL;

CREATE TABLE IF NOT EXISTS profiles.group_custom_roles (
  permission_group_id uuid NOT NULL REFERENCES profiles.permission_groups(id) ON DELETE CASCADE,
  role text NOT NULL,
  permissions text[] NOT NULL DEFAULT '{}',
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (permission_group_id, role),
  CONSTRAINT gcr_role_format_chk CHECK (role ~ '^[a-z][a-z0-9-]*$')
);

-- Invite LINKS (#134/#147): a high-entropy, unbound, single-use code that, when
-- redeemed by a logged-in user, grants `role` in the group. Possession of the
-- link is the credential; email/SMS delivery is only a convenience outside this
-- table. The plaintext code is shown to the minter ONCE; only its sha256 hex is
-- stored. invited_by CASCADEs so a user hard-delete clears the links they minted.
CREATE TABLE IF NOT EXISTS profiles.group_invite_links (
  id uuid PRIMARY KEY DEFAULT uuidv7(),
  permission_group_id uuid NOT NULL REFERENCES profiles.permission_groups(id) ON DELETE CASCADE,
  role text NOT NULL,
  invited_by uuid NOT NULL REFERENCES profiles.users(id) ON DELETE CASCADE,
  code_hash text NOT NULL UNIQUE,
  uses integer NOT NULL DEFAULT 0,
  expires_at timestamptz,
  revoked_at timestamptz,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  CONSTRAINT gil_role_format_chk CHECK (role ~ '^[a-z][a-z0-9-]*$'),
  CONSTRAINT gil_single_use_chk CHECK (uses IN (0, 1))
);
CREATE INDEX IF NOT EXISTS group_invite_links_group_idx
  ON profiles.group_invite_links (permission_group_id)
  WHERE revoked_at IS NULL;

-- Account-registration invites (#147): a standalone high-entropy token that
-- allows one email address to create an account while NativeUserRegistrationMode
-- is invite_only. These are deliberately separate from permission-group invite
-- links; creating an account never auto-redeems a group invite.
CREATE TABLE IF NOT EXISTS profiles.account_registration_invites (
  id uuid PRIMARY KEY DEFAULT uuidv7(),
  email public.citext NOT NULL,
  invited_by uuid NOT NULL REFERENCES profiles.users(id) ON DELETE CASCADE,
  code_hash text NOT NULL UNIQUE,
  expires_at timestamptz NOT NULL,
  revoked_at timestamptz,
  consumed_at timestamptz,
  consumed_by uuid REFERENCES profiles.users(id) ON DELETE SET NULL,
  -- #147: an account-registration code MAY also carry a permission-group grant, so
  -- ONE unbound single-use link registers a stranger AND joins them to a group on
  -- consume. All three are set together or all NULL (a pure registration invite).
  grant_persona text,
  grant_instance_slug text,
  grant_role text,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  CONSTRAINT account_reg_invite_grant_all_or_none_chk CHECK (
    (grant_persona IS NULL AND grant_instance_slug IS NULL AND grant_role IS NULL)
    OR (grant_persona IS NOT NULL AND grant_role IS NOT NULL)
  )
);
CREATE INDEX IF NOT EXISTS account_registration_invites_email_idx
  ON profiles.account_registration_invites (email, expires_at)
  WHERE revoked_at IS NULL AND consumed_at IS NULL;

-- #147: known-user permission-group invites. The invitee already has an account,
-- so this carries NO token — the pending row is keyed to user_id and the recipient
-- accepts/declines with their OWN auth token (authenticated AS that user is the
-- credential). Distinct from the stranger account_registration_invites code.
CREATE TABLE IF NOT EXISTS profiles.group_membership_invites (
  id uuid PRIMARY KEY DEFAULT uuidv7(),
  permission_group_id uuid NOT NULL REFERENCES profiles.permission_groups(id) ON DELETE CASCADE,
  user_id uuid NOT NULL REFERENCES profiles.users(id) ON DELETE CASCADE,
  role text NOT NULL,
  invited_by uuid NOT NULL REFERENCES profiles.users(id) ON DELETE CASCADE,
  expires_at timestamptz NOT NULL,
  accepted_at timestamptz,
  declined_at timestamptz,
  revoked_at timestamptz,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now()
);
-- At most one PENDING invite per (group, user, role).
CREATE UNIQUE INDEX IF NOT EXISTS group_membership_invites_pending_uidx
  ON profiles.group_membership_invites (permission_group_id, user_id, role)
  WHERE accepted_at IS NULL AND declined_at IS NULL AND revoked_at IS NULL;
CREATE INDEX IF NOT EXISTS group_membership_invites_user_pending_idx
  ON profiles.group_membership_invites (user_id)
  WHERE accepted_at IS NULL AND declined_at IS NULL AND revoked_at IS NULL;

CREATE TABLE IF NOT EXISTS profiles.api_keys (
  id uuid PRIMARY KEY DEFAULT uuidv7(),
  permission_group_id uuid NOT NULL REFERENCES profiles.permission_groups(id) ON DELETE CASCADE,
  key_id text NOT NULL UNIQUE,
  secret_hash bytea NOT NULL,
  name text NOT NULL,
  created_by uuid REFERENCES profiles.users(id) ON DELETE SET NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  last_used_at timestamptz,
  expires_at timestamptz,
  revoked_at timestamptz,
  role text NOT NULL,
  CONSTRAINT api_keys_name_len_chk CHECK (char_length(name) BETWEEN 1 AND 128),
  CONSTRAINT api_keys_role_format_chk CHECK (
    char_length(role) BETWEEN 1 AND 64
    AND role ~ '^[a-zA-Z0-9:_-]+$'
  )
);
CREATE INDEX IF NOT EXISTS api_keys_group_idx
  ON profiles.api_keys (permission_group_id);
-- #125: api_keys_group_role_idx (permission_group_id, role) removed —
-- no query filters by role; api_keys_group_idx covers every access.
COMMENT ON COLUMN profiles.api_keys.role IS
  'The single catalog/custom role this API key holds within its permission-group.';
