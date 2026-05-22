-- AuthKit PostgreSQL baseline schema.
--
-- PostgreSQL 18+ is required. The schema uses native uuidv7() defaults.

SET lock_timeout = '10s';
SET statement_timeout = '300s';

CREATE EXTENSION IF NOT EXISTS citext WITH SCHEMA public;
CREATE EXTENSION IF NOT EXISTS pgcrypto WITH SCHEMA public;

CREATE SCHEMA IF NOT EXISTS profiles;

CREATE TABLE IF NOT EXISTS profiles.users (
  id                uuid PRIMARY KEY DEFAULT uuidv7(),
  email             public.citext,
  username          public.citext UNIQUE,
  discord_username  text,
  email_verified    boolean NOT NULL DEFAULT false,
  phone_number      text UNIQUE,
  phone_verified    boolean DEFAULT false,
  banned_at         timestamptz,
  banned_until      timestamptz,
  ban_reason        text,
  banned_by         uuid REFERENCES profiles.users(id) ON DELETE SET NULL,
  deleted_at        timestamptz,
  biography         text,
  metadata          jsonb NOT NULL DEFAULT '{}'::jsonb,
  created_at        timestamptz NOT NULL DEFAULT now(),
  updated_at        timestamptz NOT NULL DEFAULT now(),
  last_login        timestamptz
);
CREATE UNIQUE INDEX IF NOT EXISTS users_email_uidx
  ON profiles.users (email)
  WHERE email IS NOT NULL;
COMMENT ON COLUMN profiles.users.phone_number IS 'E.164 format phone number (e.g., +14155551234)';
COMMENT ON COLUMN profiles.users.phone_verified IS 'Whether the phone number has been verified via SMS code';
COMMENT ON COLUMN profiles.users.banned_at IS 'When the user was banned';
COMMENT ON COLUMN profiles.users.banned_until IS 'When a temporary ban expires (NULL for permanent)';
COMMENT ON COLUMN profiles.users.ban_reason IS 'Reason for ban';
COMMENT ON COLUMN profiles.users.banned_by IS 'User ID of admin who imposed ban';
COMMENT ON COLUMN profiles.users.metadata IS 'Arbitrary user metadata (internal/admin flags such as reserved)';

CREATE TABLE IF NOT EXISTS profiles.user_passwords (
  user_id             uuid PRIMARY KEY REFERENCES profiles.users(id) ON DELETE CASCADE,
  password_hash       text NOT NULL,
  hash_algo           text NOT NULL DEFAULT 'argon2id',
  hash_params         jsonb,
  password_updated_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS profiles.user_providers (
  id                uuid PRIMARY KEY DEFAULT uuidv7(),
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
CREATE INDEX IF NOT EXISTS user_providers_user_id_idx
  ON profiles.user_providers (user_id);
CREATE INDEX IF NOT EXISTS user_providers_user_id_provider_slug_idx
  ON profiles.user_providers (user_id, provider_slug);

CREATE TABLE IF NOT EXISTS profiles.global_roles (
  id          uuid PRIMARY KEY DEFAULT uuidv7(),
  name        text NOT NULL,
  slug        text NOT NULL UNIQUE,
  description text,
  created_at  timestamptz NOT NULL DEFAULT now(),
  updated_at  timestamptz NOT NULL DEFAULT now(),
  deleted_at  timestamptz,
  CONSTRAINT global_roles_slug_not_owner_chk CHECK (lower(slug) <> 'owner')
);

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

CREATE OR REPLACE FUNCTION profiles.trg_global_roles_set_id_from_slug() RETURNS trigger
 LANGUAGE plpgsql
 AS $$
BEGIN
  NEW.id := profiles.role_id(NEW.slug);
  RETURN NEW;
END;
$$;

DROP TRIGGER IF EXISTS global_roles_set_id_from_slug ON profiles.global_roles;
CREATE TRIGGER global_roles_set_id_from_slug
  BEFORE INSERT ON profiles.global_roles
  FOR EACH ROW
  EXECUTE FUNCTION profiles.trg_global_roles_set_id_from_slug();

CREATE OR REPLACE FUNCTION profiles.trg_global_roles_slug_immutable() RETURNS trigger
 LANGUAGE plpgsql
 AS $$
BEGIN
  IF NEW.slug IS DISTINCT FROM OLD.slug THEN
    RAISE EXCEPTION 'profiles.global_roles.slug is immutable';
  END IF;
  RETURN NEW;
END;
$$;

DROP TRIGGER IF EXISTS global_roles_slug_immutable ON profiles.global_roles;
CREATE TRIGGER global_roles_slug_immutable
  BEFORE UPDATE OF slug ON profiles.global_roles
  FOR EACH ROW
  EXECUTE FUNCTION profiles.trg_global_roles_slug_immutable();

INSERT INTO profiles.global_roles (name, slug, description)
VALUES ('Admin', 'admin', 'Global platform administrator')
ON CONFLICT (slug) DO NOTHING;

CREATE TABLE IF NOT EXISTS profiles.global_user_roles (
  id         uuid PRIMARY KEY DEFAULT uuidv7(),
  user_id    uuid NOT NULL REFERENCES profiles.users(id) ON DELETE CASCADE,
  role_id    uuid NOT NULL REFERENCES profiles.global_roles(id) ON DELETE CASCADE,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  UNIQUE (user_id, role_id)
);

CREATE TABLE IF NOT EXISTS profiles.refresh_sessions (
  id                    uuid PRIMARY KEY DEFAULT uuidv7(),
  user_id               uuid NOT NULL REFERENCES profiles.users(id) ON DELETE CASCADE,
  issuer                text NOT NULL,
  family_id             uuid NOT NULL DEFAULT uuidv7(),
  current_token_hash    bytea NOT NULL,
  previous_token_hash   bytea,
  created_at            timestamptz NOT NULL DEFAULT now(),
  last_authenticated_at timestamptz,
  last_used_at          timestamptz NOT NULL DEFAULT now(),
  expires_at            timestamptz,
  revoked_at            timestamptz,
  user_agent            text,
  ip_addr               inet
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
  user_id      uuid PRIMARY KEY REFERENCES profiles.users(id) ON DELETE CASCADE,
  enabled      boolean NOT NULL DEFAULT false,
  method       varchar(10) NOT NULL DEFAULT 'email' CHECK (method IN ('email', 'sms')),
  phone_number varchar(20),
  backup_codes text[],
  created_at   timestamptz NOT NULL DEFAULT now(),
  updated_at   timestamptz NOT NULL DEFAULT now(),
  CONSTRAINT phone_required_for_sms CHECK (
    (method = 'sms' AND phone_number IS NOT NULL) OR
    (method = 'email')
  )
);
CREATE INDEX IF NOT EXISTS idx_two_factor_settings_enabled
  ON profiles.two_factor_settings(enabled)
  WHERE enabled = true;
COMMENT ON TABLE profiles.two_factor_settings IS 'Two-factor authentication settings per user (admin accounts)';
COMMENT ON COLUMN profiles.two_factor_settings.method IS 'Preferred 2FA method: email or sms';
COMMENT ON COLUMN profiles.two_factor_settings.backup_codes IS 'Hashed backup codes for account recovery (10 codes)';

CREATE TABLE IF NOT EXISTS profiles.orgs (
  id            uuid PRIMARY KEY DEFAULT uuidv7(),
  slug          text NOT NULL UNIQUE,
  is_personal   boolean NOT NULL DEFAULT false,
  owner_user_id uuid REFERENCES profiles.users(id) ON DELETE RESTRICT,
  metadata      jsonb NOT NULL DEFAULT '{}'::jsonb,
  created_at    timestamptz NOT NULL DEFAULT now(),
  updated_at    timestamptz NOT NULL DEFAULT now(),
  deleted_at    timestamptz,
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
  ON profiles.orgs(owner_user_id)
  WHERE is_personal = true AND deleted_at IS NULL;
COMMENT ON COLUMN profiles.orgs.metadata IS 'Arbitrary org metadata (internal/admin flags such as reserved)';

CREATE TABLE IF NOT EXISTS profiles.org_members (
  org_id     uuid NOT NULL REFERENCES profiles.orgs(id) ON DELETE CASCADE,
  user_id    uuid NOT NULL REFERENCES profiles.users(id) ON DELETE CASCADE,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  deleted_at timestamptz,
  UNIQUE (org_id, user_id)
);
CREATE INDEX IF NOT EXISTS org_members_user_id_idx
  ON profiles.org_members (user_id)
  WHERE deleted_at IS NULL;

CREATE TABLE IF NOT EXISTS profiles.org_roles (
  org_id     uuid NOT NULL REFERENCES profiles.orgs(id) ON DELETE CASCADE,
  role       text NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  UNIQUE (org_id, role),
  CONSTRAINT org_roles_role_format_chk CHECK (
    char_length(role) BETWEEN 1 AND 64
    AND role ~ '^[a-zA-Z0-9:_-]+$'
  )
);

CREATE TABLE IF NOT EXISTS profiles.org_member_roles (
  org_id     uuid NOT NULL,
  user_id    uuid NOT NULL,
  role       text NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  UNIQUE (org_id, user_id, role),
  FOREIGN KEY (org_id, user_id) REFERENCES profiles.org_members(org_id, user_id) ON DELETE CASCADE,
  FOREIGN KEY (org_id, role) REFERENCES profiles.org_roles(org_id, role) ON DELETE CASCADE,
  CONSTRAINT org_member_roles_role_format_chk CHECK (
    char_length(role) BETWEEN 1 AND 64
    AND role ~ '^[a-zA-Z0-9:_-]+$'
  )
);
CREATE INDEX IF NOT EXISTS org_member_roles_member_idx
  ON profiles.org_member_roles (org_id, user_id);
CREATE INDEX IF NOT EXISTS org_member_roles_org_idx
  ON profiles.org_member_roles (org_id);

CREATE TABLE IF NOT EXISTS profiles.org_invites (
  id         uuid PRIMARY KEY DEFAULT uuidv7(),
  org_id     uuid NOT NULL REFERENCES profiles.orgs(id) ON DELETE CASCADE,
  user_id    uuid NOT NULL REFERENCES profiles.users(id) ON DELETE CASCADE,
  invited_by uuid NOT NULL REFERENCES profiles.users(id) ON DELETE RESTRICT,
  role       text NOT NULL DEFAULT 'member',
  status     text NOT NULL DEFAULT 'pending',
  expires_at timestamptz,
  acted_at   timestamptz,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  deleted_at timestamptz,
  CONSTRAINT org_invites_status_chk CHECK (status IN ('pending', 'accepted', 'declined', 'revoked', 'expired')),
  CONSTRAINT org_invites_role_format_chk CHECK (
    char_length(role) BETWEEN 1 AND 64
    AND role ~ '^[a-zA-Z0-9:_-]+$'
  ),
  -- Role must be one the org actually defines; cascade so deleting a role
  -- clears any invites that targeted it.
  FOREIGN KEY (org_id, role) REFERENCES profiles.org_roles(org_id, role) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS org_invites_org_idx
  ON profiles.org_invites(org_id)
  WHERE deleted_at IS NULL;
CREATE INDEX IF NOT EXISTS org_invites_user_idx
  ON profiles.org_invites(user_id)
  WHERE deleted_at IS NULL;
CREATE INDEX IF NOT EXISTS org_invites_status_idx
  ON profiles.org_invites(status)
  WHERE deleted_at IS NULL;
CREATE UNIQUE INDEX IF NOT EXISTS org_invites_pending_org_user_uidx
  ON profiles.org_invites(org_id, user_id)
  WHERE status = 'pending' AND deleted_at IS NULL;

CREATE TABLE IF NOT EXISTS profiles.owner_reserved_names (
  slug       text PRIMARY KEY,
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
  id         bigserial PRIMARY KEY,
  org_id     uuid NOT NULL REFERENCES profiles.orgs(id) ON DELETE CASCADE,
  from_slug  text NOT NULL,
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
  id         bigserial PRIMARY KEY,
  user_id    uuid NOT NULL REFERENCES profiles.users(id) ON DELETE CASCADE,
  from_slug  text NOT NULL,
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

-- Federated-org issuer registry.
--
-- A federated org "brings its own" users that authenticate via the org's OWN
-- issuer (not local passwords). The org registers its issuer URL + JWKS URL
-- here; a resource-server-side AuthKit then trusts delegated tokens minted by
-- that issuer (carrying `delegated_sub`). This table is the resource-server's
-- store of accepted federated issuers — it replaces a bespoke per-app table
-- (e.g. tensorhub's `platform_issuers`). The Verifier loads `active` rows from
-- here and registers each as a trusted issuer (with the org's JWKS URL), so its
-- existing in-house JWKS fetch/refresh handles federated keys with NO external
-- push/sync.
CREATE TABLE IF NOT EXISTS profiles.federated_org_issuers (
  id         uuid PRIMARY KEY DEFAULT uuidv7(),
  -- Org identity as presented by the registering platform. `org_slug` is the
  -- tenant slug carried in delegated tokens (`org`/`tenant`); it is NOT a FK to
  -- profiles.orgs because a federated org lives in the remote platform, not
  -- locally.
  org_slug   text NOT NULL,
  -- issuer_id is the `iss` URL the federated platform signs delegated tokens
  -- with; it is the trust anchor and is globally unique.
  issuer_id  text NOT NULL UNIQUE,
  jwks_url   text NOT NULL,
  status     text NOT NULL DEFAULT 'active',
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  CONSTRAINT federated_org_issuers_status_chk CHECK (status IN ('active', 'inactive')),
  CONSTRAINT federated_org_issuers_org_slug_format_chk CHECK (
    char_length(org_slug) BETWEEN 1 AND 63
    AND org_slug ~ '^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$'
  )
);
CREATE INDEX IF NOT EXISTS federated_org_issuers_org_slug_idx
  ON profiles.federated_org_issuers (org_slug);
CREATE INDEX IF NOT EXISTS federated_org_issuers_status_idx
  ON profiles.federated_org_issuers (status)
  WHERE status = 'active';
COMMENT ON TABLE profiles.federated_org_issuers IS 'Registry of trusted federated-org issuers (delegated-token federation). Resource-server side.';
