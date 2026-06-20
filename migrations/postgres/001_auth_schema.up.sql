-- AuthKit PostgreSQL schema.
-- PostgreSQL 18+ is required for native uuidv7() defaults.

SET lock_timeout = '10s';
SET statement_timeout = '300s';

CREATE EXTENSION IF NOT EXISTS citext WITH SCHEMA public;
CREATE EXTENSION IF NOT EXISTS pgcrypto WITH SCHEMA public;

CREATE SCHEMA IF NOT EXISTS profiles;

CREATE OR REPLACE FUNCTION profiles.uuid_v5(p_namespace uuid, p_name text) RETURNS uuid
LANGUAGE plpgsql
IMMUTABLE
STRICT
AS $$
DECLARE
  h bytea;
  b bytea;
  hex text;
BEGIN
  h := digest(uuid_send(p_namespace) || convert_to(p_name, 'utf8'), 'sha1');
  b := substring(h from 1 for 16);
  b := set_byte(b, 6, (get_byte(b, 6) & 15) | 80);
  b := set_byte(b, 8, (get_byte(b, 8) & 63) | 128);
  hex := encode(b, 'hex');
  RETURN (
    substring(hex from 1 for 8) || '-' ||
    substring(hex from 9 for 4) || '-' ||
    substring(hex from 13 for 4) || '-' ||
    substring(hex from 17 for 4) || '-' ||
    substring(hex from 21 for 12)
  )::uuid;
END;
$$;

CREATE OR REPLACE FUNCTION profiles.role_id(p_slug text) RETURNS uuid
LANGUAGE sql
IMMUTABLE
STRICT
AS $$
  SELECT profiles.uuid_v5('ef5d0f45-83c6-5dbe-b15a-e017bc88ab5a'::uuid, 'role:' || p_slug);
$$;

CREATE TABLE IF NOT EXISTS profiles.users (
  id uuid PRIMARY KEY DEFAULT uuidv7(),
  email public.citext,
  username public.citext UNIQUE,
  discord_username text,
  email_verified boolean NOT NULL DEFAULT false,
  phone_number text UNIQUE,
  phone_verified boolean DEFAULT false,
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
  preferred_locale text,
  preferred_locale_source text,
  preferred_locale_updated_at timestamptz
);
CREATE UNIQUE INDEX IF NOT EXISTS users_email_uidx ON profiles.users (email) WHERE email IS NOT NULL;
COMMENT ON COLUMN profiles.users.phone_number IS 'E.164 format phone number (e.g., +14155551234)';
COMMENT ON COLUMN profiles.users.phone_verified IS 'Whether the phone number has been verified via SMS code';
COMMENT ON COLUMN profiles.users.banned_at IS 'When the user was banned';
COMMENT ON COLUMN profiles.users.banned_until IS 'When a temporary ban expires (NULL for permanent)';
COMMENT ON COLUMN profiles.users.ban_reason IS 'Reason for ban';
COMMENT ON COLUMN profiles.users.banned_by IS 'User ID of admin who imposed ban';
COMMENT ON COLUMN profiles.users.metadata IS 'Arbitrary user metadata (internal/admin flags such as reserved)';
COMMENT ON COLUMN profiles.users.preferred_locale IS 'User communication/auth locale, e.g. en, es, de, ko, zh-CN';
COMMENT ON COLUMN profiles.users.preferred_locale_source IS 'Source of preferred_locale, e.g. registration or explicit';
COMMENT ON COLUMN profiles.users.preferred_locale_updated_at IS 'When preferred_locale was last set';

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
CREATE INDEX IF NOT EXISTS user_providers_user_id_idx ON profiles.user_providers (user_id);
CREATE INDEX IF NOT EXISTS user_providers_user_id_provider_slug_idx
  ON profiles.user_providers (user_id, provider_slug);

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
  ip_addr inet
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

CREATE TABLE IF NOT EXISTS profiles.two_factor_settings (
  user_id uuid PRIMARY KEY REFERENCES profiles.users(id) ON DELETE CASCADE,
  enabled boolean NOT NULL DEFAULT false,
  method varchar(10) NOT NULL DEFAULT 'email' CHECK (method IN ('email', 'sms')),
  phone_number varchar(20),
  backup_codes text[],
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  CONSTRAINT phone_required_for_sms CHECK (
    (method = 'sms' AND phone_number IS NOT NULL) OR method = 'email'
  )
);
CREATE INDEX IF NOT EXISTS idx_two_factor_settings_enabled
  ON profiles.two_factor_settings (enabled)
  WHERE enabled = true;
COMMENT ON TABLE profiles.two_factor_settings IS 'Two-factor authentication settings per user (admin accounts)';
COMMENT ON COLUMN profiles.two_factor_settings.method IS 'Preferred 2FA method: email or sms';
COMMENT ON COLUMN profiles.two_factor_settings.backup_codes IS 'Hashed backup codes for account recovery (10 codes)';

CREATE TABLE IF NOT EXISTS profiles.orgs (
  id uuid PRIMARY KEY DEFAULT uuidv7(),
  slug text NOT NULL UNIQUE,
  is_personal boolean NOT NULL DEFAULT false,
  owner_user_id uuid REFERENCES profiles.users(id) ON DELETE RESTRICT,
  metadata jsonb NOT NULL DEFAULT '{}'::jsonb,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  deleted_at timestamptz,
  CONSTRAINT orgs_slug_format_chk CHECK (
    char_length(slug) BETWEEN 1 AND 63
    AND slug ~ '^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$'
  ),
  CONSTRAINT orgs_personal_owner_chk CHECK (
    (is_personal = true AND owner_user_id IS NOT NULL)
    OR (is_personal = false AND owner_user_id IS NULL)
  )
);
CREATE UNIQUE INDEX IF NOT EXISTS orgs_owner_user_personal_uidx
  ON profiles.orgs (owner_user_id)
  WHERE is_personal = true AND deleted_at IS NULL;
COMMENT ON COLUMN profiles.orgs.metadata IS 'Arbitrary org metadata (internal/admin flags such as reserved)';

CREATE TABLE IF NOT EXISTS profiles.org_roles (
  org_id uuid NOT NULL REFERENCES profiles.orgs(id) ON DELETE CASCADE,
  role text NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  UNIQUE (org_id, role),
  CONSTRAINT org_roles_role_format_chk CHECK (
    char_length(role) BETWEEN 1 AND 64
    AND role ~ '^[a-zA-Z0-9:_-]+$'
  )
);

CREATE TABLE IF NOT EXISTS profiles.org_role_permissions (
  org_id uuid NOT NULL,
  role text NOT NULL,
  permission text NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  UNIQUE (org_id, role, permission),
  FOREIGN KEY (org_id, role) REFERENCES profiles.org_roles(org_id, role) ON DELETE CASCADE,
  CONSTRAINT org_role_permissions_perm_len_chk CHECK (char_length(permission) BETWEEN 1 AND 128)
);
CREATE INDEX IF NOT EXISTS org_role_permissions_role_idx
  ON profiles.org_role_permissions (org_id, role);

CREATE TABLE IF NOT EXISTS profiles.org_memberships (
  org_id uuid NOT NULL REFERENCES profiles.orgs(id) ON DELETE CASCADE,
  member_id uuid NOT NULL,
  role text NOT NULL DEFAULT 'member',
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  deleted_at timestamptz,
  member_kind text NOT NULL DEFAULT 'user',
  FOREIGN KEY (org_id, role) REFERENCES profiles.org_roles(org_id, role) ON DELETE CASCADE,
  CONSTRAINT org_memberships_member_kind_chk CHECK (member_kind IN ('user', 'remote_application')),
  CONSTRAINT org_memberships_role_format_chk CHECK (
    char_length(role) BETWEEN 1 AND 64
    AND role ~ '^[a-zA-Z0-9:_-]+$'
  )
);
CREATE UNIQUE INDEX IF NOT EXISTS org_memberships_org_member_uidx
  ON profiles.org_memberships (org_id, member_id, member_kind);
CREATE INDEX IF NOT EXISTS org_memberships_member_idx
  ON profiles.org_memberships (member_id, member_kind)
  WHERE deleted_at IS NULL;
CREATE INDEX IF NOT EXISTS org_memberships_org_role_idx
  ON profiles.org_memberships (org_id, role)
  WHERE deleted_at IS NULL;
COMMENT ON COLUMN profiles.org_memberships.member_id IS 'Principal id; referent table named by member_kind.';
COMMENT ON COLUMN profiles.org_memberships.member_kind IS 'Principal kind: user | remote_application. One membership system serves both.';

CREATE TABLE IF NOT EXISTS profiles.remote_applications (
  id uuid PRIMARY KEY DEFAULT uuidv7(),
  slug text NOT NULL UNIQUE,
  issuer text NOT NULL UNIQUE,
  jwks_uri text NOT NULL DEFAULT '',
  mode text NOT NULL DEFAULT 'jwks',
  public_keys jsonb,
  audiences text[] NOT NULL DEFAULT '{}',
  enabled boolean NOT NULL DEFAULT true,
  metadata jsonb NOT NULL DEFAULT '{}'::jsonb,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  deleted_at timestamptz,
  org_id uuid REFERENCES profiles.orgs(id),
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
CREATE INDEX IF NOT EXISTS remote_applications_org_idx
  ON profiles.remote_applications (org_id);
COMMENT ON TABLE profiles.remote_applications IS
  'Federation principals: external systems that authenticate by signing JWTs verified against their JWKS/public keys. Members of orgs with roles via polymorphic org_memberships.';
COMMENT ON COLUMN profiles.remote_applications.org_id IS
  'Optional controlling org. NULL = bootstrap/operator-managed issuer with no AuthKit user/org owner; SET = org-controlled issuer managed through org RBAC.';

CREATE OR REPLACE FUNCTION profiles.trg_org_membership_member_fk() RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
  IF NEW.member_kind = 'user' THEN
    IF NOT EXISTS (SELECT 1 FROM profiles.users WHERE id = NEW.member_id) THEN
      RAISE EXCEPTION 'org_memberships.member_id % is not a profiles.users row', NEW.member_id
        USING ERRCODE = 'foreign_key_violation';
    END IF;
  ELSIF NEW.member_kind = 'remote_application' THEN
    IF NOT EXISTS (SELECT 1 FROM profiles.remote_applications WHERE id = NEW.member_id) THEN
      RAISE EXCEPTION 'org_memberships.member_id % is not a profiles.remote_applications row', NEW.member_id
        USING ERRCODE = 'foreign_key_violation';
    END IF;
  END IF;
  RETURN NEW;
END;
$$;

DROP TRIGGER IF EXISTS org_membership_member_fk ON profiles.org_memberships;
CREATE TRIGGER org_membership_member_fk
  BEFORE INSERT OR UPDATE OF member_id, member_kind ON profiles.org_memberships
  FOR EACH ROW
  EXECUTE FUNCTION profiles.trg_org_membership_member_fk();

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
  'REFERENCE-mode attribute definitions: (remote_application_id, key, version) -> opaque definition jsonb. AuthKit transports + serves, never interprets (#75).';

CREATE TABLE IF NOT EXISTS profiles.remote_application_permissions (
  remote_application_id uuid NOT NULL REFERENCES profiles.remote_applications(id) ON DELETE CASCADE,
  permission text NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (remote_application_id, permission),
  CONSTRAINT rap_permission_format_chk CHECK (char_length(permission) BETWEEN 1 AND 256)
);
CREATE INDEX IF NOT EXISTS rap_app_idx
  ON profiles.remote_application_permissions (remote_application_id);
COMMENT ON TABLE profiles.remote_application_permissions IS
  'Direct permissions assigned to a remote_application principal (#76): STORED authority for the JWKS self-token, mirroring service_token_permissions. Opaque to AuthKit.';

CREATE TABLE IF NOT EXISTS profiles.service_tokens (
  id uuid PRIMARY KEY DEFAULT uuidv7(),
  org_id uuid NOT NULL REFERENCES profiles.orgs(id) ON DELETE CASCADE,
  key_id text NOT NULL UNIQUE,
  secret_hash bytea NOT NULL,
  name text NOT NULL,
  created_by uuid REFERENCES profiles.users(id) ON DELETE SET NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  last_used_at timestamptz,
  expires_at timestamptz,
  revoked_at timestamptz,
  CONSTRAINT service_tokens_name_len_chk CHECK (char_length(name) BETWEEN 1 AND 128)
);
CREATE INDEX IF NOT EXISTS service_tokens_org_idx ON profiles.service_tokens (org_id);

CREATE TABLE IF NOT EXISTS profiles.service_token_resources (
  token_id uuid NOT NULL REFERENCES profiles.service_tokens(id) ON DELETE CASCADE,
  kind text NOT NULL,
  resource_id text NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (token_id, kind, resource_id),
  CONSTRAINT service_token_resources_kind_len_chk CHECK (char_length(kind) BETWEEN 1 AND 128),
  CONSTRAINT service_token_resources_resource_id_len_chk CHECK (char_length(resource_id) BETWEEN 1 AND 128)
);
CREATE INDEX IF NOT EXISTS service_token_resources_token_idx
  ON profiles.service_token_resources (token_id);

CREATE TABLE IF NOT EXISTS profiles.service_token_permissions (
  service_token_id uuid NOT NULL REFERENCES profiles.service_tokens(id) ON DELETE CASCADE,
  permission text NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (service_token_id, permission),
  CONSTRAINT service_token_permissions_perm_len_chk CHECK (char_length(permission) BETWEEN 1 AND 128)
);
CREATE INDEX IF NOT EXISTS service_token_permissions_token_idx
  ON profiles.service_token_permissions (service_token_id);

CREATE TABLE IF NOT EXISTS profiles.org_invites (
  id uuid PRIMARY KEY DEFAULT uuidv7(),
  org_id uuid NOT NULL REFERENCES profiles.orgs(id) ON DELETE CASCADE,
  user_id uuid NOT NULL REFERENCES profiles.users(id) ON DELETE CASCADE,
  invited_by uuid NOT NULL REFERENCES profiles.users(id) ON DELETE RESTRICT,
  role text NOT NULL DEFAULT 'member',
  status text NOT NULL DEFAULT 'pending',
  expires_at timestamptz,
  acted_at timestamptz,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  deleted_at timestamptz,
  FOREIGN KEY (org_id, role) REFERENCES profiles.org_roles(org_id, role) ON DELETE CASCADE,
  CONSTRAINT org_invites_status_chk CHECK (status IN ('pending', 'accepted', 'declined', 'revoked', 'expired')),
  CONSTRAINT org_invites_role_format_chk CHECK (
    char_length(role) BETWEEN 1 AND 64
    AND role ~ '^[a-zA-Z0-9:_-]+$'
  )
);
CREATE INDEX IF NOT EXISTS org_invites_org_idx ON profiles.org_invites (org_id) WHERE deleted_at IS NULL;
CREATE INDEX IF NOT EXISTS org_invites_user_idx ON profiles.org_invites (user_id) WHERE deleted_at IS NULL;
CREATE INDEX IF NOT EXISTS org_invites_status_idx ON profiles.org_invites (status) WHERE deleted_at IS NULL;
CREATE UNIQUE INDEX IF NOT EXISTS org_invites_pending_org_user_uidx
  ON profiles.org_invites (org_id, user_id)
  WHERE status = 'pending' AND deleted_at IS NULL;

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

CREATE TABLE IF NOT EXISTS profiles.org_renames (
  id bigserial PRIMARY KEY,
  org_id uuid NOT NULL REFERENCES profiles.orgs(id) ON DELETE CASCADE,
  from_slug text NOT NULL,
  renamed_at timestamptz NOT NULL DEFAULT now(),
  CONSTRAINT org_renames_from_slug_format_chk CHECK (
    from_slug = lower(from_slug)
    AND from_slug ~ '^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$'
  )
);
CREATE INDEX IF NOT EXISTS org_renames_from_renamed_idx
  ON profiles.org_renames (from_slug, renamed_at DESC);
CREATE INDEX IF NOT EXISTS org_renames_org_idx
  ON profiles.org_renames (org_id, renamed_at DESC);

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
