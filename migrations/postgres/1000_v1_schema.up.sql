-- parent: root
-- AuthKit v1 fresh PostgreSQL 18+ schema. Earlier prerelease schemas are unsupported.
-- Migration is transactional; it never drops or adopts existing AuthKit tables.
DO $$
BEGIN
  IF EXISTS (
    SELECT 1 FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
    WHERE n.nspname = 'profiles' AND c.relname IN (
      'account_registration_invites',
      'api_keys',
      'bootstrap_applies',
      'group_custom_roles',
      'group_invite_links',
      'group_membership_invites',
      'group_persona_parents',
      'group_remote_application_roles',
      'group_user_roles',
      'mfa_factors',
      'mfa_settings',
      'name_claims',
      'permission_group_slug_tombstones',
      'permission_groups',
      'refresh_sessions',
      'refresh_token_history',
      'remote_application_attribute_defs',
      'remote_applications',
      'session_events',
      'signed_documents',
      'user_device_keys',
      'user_passkey_handles',
      'user_passkeys',
      'user_passwords',
      'user_providers',
      'user_renames',
      'users'
    )
  ) THEN
    RAISE EXCEPTION 'unsupported AuthKit schema: use a fresh AuthKit schema and reset only its scoped migration ledger'
      USING ERRCODE = '55000';
  END IF;
END;
$$;

SET LOCAL lock_timeout = '10s';
SET LOCAL statement_timeout = '300s';

CREATE EXTENSION IF NOT EXISTS citext WITH SCHEMA public;
CREATE EXTENSION IF NOT EXISTS pgcrypto WITH SCHEMA public;

CREATE SCHEMA IF NOT EXISTS profiles;

-- Bootstrap ownership
CREATE TABLE profiles.bootstrap_applies (
  name text PRIMARY KEY,
  applied_at timestamptz NOT NULL DEFAULT now()
);

-- Identity and password credentials
CREATE TABLE profiles.users (
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
  metadata jsonb NOT NULL DEFAULT '{}'::jsonb,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  last_login timestamptz,
  preferred_language text,
  avatar_url text,
  last_renamed_at timestamptz,
  credential_version bigint NOT NULL DEFAULT 1 CHECK (credential_version > 0)
);
CREATE UNIQUE INDEX users_email_uidx
  ON profiles.users (email)
  WHERE email IS NOT NULL;
CREATE INDEX users_admin_created_idx
  ON profiles.users (created_at DESC, id)
  WHERE deleted_at IS NULL;
CREATE INDEX users_admin_last_login_idx
  ON profiles.users (last_login DESC, id)
  WHERE deleted_at IS NULL;
CREATE INDEX users_admin_username_idx
  ON profiles.users (username, id)
  WHERE deleted_at IS NULL;
CREATE INDEX users_admin_email_idx
  ON profiles.users (email, id)
  WHERE deleted_at IS NULL;
CREATE INDEX users_deleted_at_idx
  ON profiles.users (deleted_at, id)
  WHERE deleted_at IS NOT NULL;
CREATE INDEX users_admin_banned_idx
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

CREATE TABLE profiles.user_passwords (
  user_id uuid PRIMARY KEY REFERENCES profiles.users(id) ON DELETE CASCADE,
  password_hash text NOT NULL,
  hash_algo text NOT NULL DEFAULT 'argon2id',
  hash_params jsonb,
  password_updated_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE profiles.user_providers (
  id uuid PRIMARY KEY DEFAULT uuidv7(),
  user_id uuid NOT NULL REFERENCES profiles.users(id) ON DELETE CASCADE,
  issuer text NOT NULL,
  provider_slug text,
  subject text NOT NULL,
  email_at_provider text,
  profile jsonb,
  created_at timestamptz NOT NULL DEFAULT now(),
  verified_at timestamptz DEFAULT now(),
  UNIQUE (issuer, subject),
  UNIQUE (user_id, issuer)
);
CREATE INDEX user_providers_user_id_provider_slug_idx
  ON profiles.user_providers (user_id, provider_slug);
CREATE INDEX user_providers_slug_subject_idx
  ON profiles.user_providers (provider_slug, subject);

-- Passkeys
CREATE TABLE profiles.user_passkey_handles (
  user_id uuid PRIMARY KEY REFERENCES profiles.users(id) ON DELETE CASCADE,
  user_handle bytea NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now()
);
CREATE UNIQUE INDEX uniq_user_passkey_handles_handle
  ON profiles.user_passkey_handles (user_handle);

CREATE TABLE profiles.user_passkeys (
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
  flags bytea NOT NULL DEFAULT '\x00',
  attestation_type text NOT NULL DEFAULT '',
  attestation_fmt text NOT NULL DEFAULT '',
  label text,
  created_at timestamptz NOT NULL DEFAULT now(),
  last_used_at timestamptz,
  deleted_at timestamptz
);
CREATE UNIQUE INDEX uniq_user_passkeys_rpid_credential
  ON profiles.user_passkeys (rpid, credential_id)
  WHERE deleted_at IS NULL;
CREATE INDEX idx_user_passkeys_user_active
  ON profiles.user_passkeys (user_id)
  WHERE deleted_at IS NULL;

-- Refresh sessions
CREATE TABLE profiles.refresh_sessions (
  id uuid PRIMARY KEY DEFAULT uuidv7(),
  user_id uuid NOT NULL REFERENCES profiles.users(id) ON DELETE CASCADE,
  issuer text NOT NULL,
  family_id uuid NOT NULL DEFAULT uuidv7(),
  current_token_hash bytea NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  last_authenticated_at timestamptz,
  last_used_at timestamptz NOT NULL DEFAULT now(),
  expires_at timestamptz,
  revoked_at timestamptz,
  user_agent text,
  ip_addr inet,
  auth_methods text[] NOT NULL DEFAULT ARRAY['pwd']::text[],
  previous_successor_sealed bytea,
  previous_rotated_at timestamptz
);
CREATE UNIQUE INDEX refresh_sessions_current_hash_active
  ON profiles.refresh_sessions (current_token_hash)
  WHERE revoked_at IS NULL;
CREATE INDEX refresh_sessions_user_active
  ON profiles.refresh_sessions (user_id, issuer, last_used_at)
  WHERE revoked_at IS NULL;
CREATE INDEX refresh_sessions_family_active
  ON profiles.refresh_sessions (family_id)
  WHERE revoked_at IS NULL;

-- Multi-factor credentials
CREATE TABLE profiles.mfa_settings (
  user_id uuid PRIMARY KEY REFERENCES profiles.users(id) ON DELETE CASCADE,
  enabled boolean NOT NULL DEFAULT false,
  backup_codes text[],
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now()
);
COMMENT ON TABLE profiles.mfa_settings IS 'Account-level 2FA gate + backup codes per user. enabled=true ⇒ 2FA required at login. Per-factor data lives in mfa_factors.';
COMMENT ON COLUMN profiles.mfa_settings.backup_codes IS 'Hashed backup codes for account recovery';

CREATE TABLE profiles.mfa_factors (
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
CREATE UNIQUE INDEX uniq_mfa_factors_default
  ON profiles.mfa_factors (user_id)
  WHERE is_default = true;
CREATE UNIQUE INDEX uniq_mfa_factors_user_method
  ON profiles.mfa_factors (user_id, method);
COMMENT ON TABLE profiles.mfa_factors IS 'Enrolled 2FA factors per user (hard-deleted on removal); backup codes remain user-scoped on mfa_settings';
COMMENT ON COLUMN profiles.mfa_factors.is_default IS 'Default factor AuthKit challenges first when 2FA is required';

-- Permission groups and containment
CREATE TABLE profiles.group_persona_parents (
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

CREATE TABLE profiles.permission_groups (
  id uuid PRIMARY KEY DEFAULT uuidv7(),
  persona text NOT NULL,
  parent_id uuid REFERENCES profiles.permission_groups(id) ON DELETE CASCADE,
  instance_slug text,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  display_name text NOT NULL DEFAULT '',
  last_renamed_at timestamptz,
  CONSTRAINT pg_persona_format_chk CHECK (persona ~ '^[a-z][a-z0-9-]*$'),
  CONSTRAINT pg_instance_slug_format_chk CHECK (
    instance_slug IS NULL OR (
      char_length(instance_slug) BETWEEN 1 AND 253
      AND instance_slug ~ '^[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?$'
      AND instance_slug NOT LIKE '%..%'
    )
  ),
  CONSTRAINT pg_root_parentless_chk CHECK (
    (persona = 'root' AND parent_id IS NULL AND instance_slug IS NULL)
    OR (persona <> 'root' AND parent_id IS NOT NULL AND instance_slug IS NOT NULL)
  )
);
CREATE UNIQUE INDEX permission_groups_persona_instance_uidx
  ON profiles.permission_groups (persona, instance_slug)
  WHERE instance_slug IS NOT NULL;
CREATE UNIQUE INDEX permission_groups_singleton_root_uidx
  ON profiles.permission_groups ((persona = 'root'))
  WHERE persona = 'root';
CREATE INDEX permission_groups_parent_idx
  ON profiles.permission_groups (parent_id)
  WHERE parent_id IS NOT NULL;
CREATE INDEX permission_groups_persona_idx
  ON profiles.permission_groups (persona);
COMMENT ON COLUMN profiles.permission_groups.instance_slug IS
  'Lowercase URL-safe slug identifying WHICH instance of the persona (e.g. acme-store for a merchant); the API addressing key. The group id is internal only.';

CREATE FUNCTION profiles.trg_permission_group_containment() RETURNS trigger
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
  IF NOT EXISTS (
    SELECT 1 FROM profiles.group_persona_parents
    WHERE persona = NEW.persona AND parent_persona = actual_parent_persona
  ) THEN
    RAISE EXCEPTION 'a % group may not have a % parent',
      NEW.persona, actual_parent_persona USING ERRCODE = 'check_violation';
  END IF;
  RETURN NEW;
END;
$$;
CREATE TRIGGER permission_group_containment
  BEFORE INSERT OR UPDATE OF persona, parent_id ON profiles.permission_groups
  FOR EACH ROW EXECUTE FUNCTION profiles.trg_permission_group_containment();

-- Federated applications
CREATE TABLE profiles.remote_applications (
  id uuid PRIMARY KEY DEFAULT uuidv7(),
  slug text NOT NULL UNIQUE,
  issuer text NOT NULL UNIQUE,
  jwks_uri text NOT NULL DEFAULT '',
  mode text NOT NULL DEFAULT 'jwks',
  public_keys jsonb,
  enabled boolean NOT NULL DEFAULT true,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  permission_group_id uuid NOT NULL REFERENCES profiles.permission_groups(id) ON DELETE CASCADE,
  display_name text NOT NULL DEFAULT '',
  tier text NOT NULL DEFAULT 'approved',
  trust_root text NOT NULL DEFAULT 'manual',
  domain text NOT NULL DEFAULT '',
  document_endpoint text NOT NULL DEFAULT '',
  root_verified_at timestamptz,
  CONSTRAINT remote_applications_tier_chk CHECK (tier IN ('registered', 'approved')),
  CONSTRAINT remote_applications_trust_root_chk CHECK (trust_root IN ('manual', 'domain', 'user')),
  CONSTRAINT remote_applications_slug_format_chk CHECK (
    char_length(slug) BETWEEN 1 AND 253
    AND slug ~ '^[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?$'
    AND slug NOT LIKE '%..%'
  ),
  CONSTRAINT remote_applications_mode_chk CHECK (mode IN ('jwks', 'static')),
  CONSTRAINT remote_applications_trust_source_xor CHECK (
    (mode = 'jwks' AND jwks_uri <> '' AND public_keys IS NULL)
    OR
    (mode = 'static' AND jwks_uri = '' AND public_keys IS NOT NULL
      AND jsonb_typeof(public_keys) = 'array' AND jsonb_array_length(public_keys) > 0)
  )
);
CREATE INDEX remote_applications_group_idx
  ON profiles.remote_applications (permission_group_id);
COMMENT ON TABLE profiles.remote_applications IS
  'Federation principals: external systems that authenticate by signing JWTs verified against configured keys.';
COMMENT ON COLUMN profiles.remote_applications.permission_group_id IS
  'Required controlling permission-group. Authority comes from group_remote_application_roles and the parent walk.';

CREATE UNIQUE INDEX remote_applications_domain_uidx
  ON profiles.remote_applications (domain)
  WHERE domain <> '';

COMMENT ON COLUMN profiles.remote_applications.tier IS
  'registered (self-registered; zero default capability) | approved (admin act on the host).';
COMMENT ON COLUMN profiles.remote_applications.trust_root IS
  'What rotates the keys: manual | domain | user. Never the keypair alone.';
COMMENT ON COLUMN profiles.remote_applications.domain IS
  'Trust-root location for domain-rooted applications (canonical registration input; empty otherwise). Separate from slug — the domain proves identity, the slug is a claimed handle.';
COMMENT ON COLUMN profiles.remote_applications.root_verified_at IS
  'Last successful trust-root proof (domain fetch). Re-verification cadence is host policy (host sweepers disable stale registered-tier apps; re-registration re-proves and re-enables).';

-- Role assignments
CREATE TABLE profiles.group_user_roles (
  permission_group_id uuid NOT NULL REFERENCES profiles.permission_groups(id) ON DELETE CASCADE,
  user_id uuid NOT NULL REFERENCES profiles.users(id) ON DELETE CASCADE,
  role text NOT NULL,
  PRIMARY KEY (permission_group_id, user_id),
  CONSTRAINT gur_role_format_chk CHECK (role ~ '^[a-z][a-z0-9-]*$')
);
CREATE INDEX gur_user_idx
  ON profiles.group_user_roles (user_id);

CREATE TABLE profiles.group_remote_application_roles (
  permission_group_id uuid NOT NULL REFERENCES profiles.permission_groups(id) ON DELETE CASCADE,
  remote_application_id uuid NOT NULL REFERENCES profiles.remote_applications(id) ON DELETE CASCADE,
  role text NOT NULL,
  PRIMARY KEY (permission_group_id, remote_application_id),
  CONSTRAINT grar_role_format_chk CHECK (role ~ '^[a-z][a-z0-9-]*$')
);
CREATE INDEX grar_remote_application_idx
  ON profiles.group_remote_application_roles (remote_application_id);

CREATE TABLE profiles.group_custom_roles (
  permission_group_id uuid NOT NULL REFERENCES profiles.permission_groups(id) ON DELETE CASCADE,
  role text NOT NULL,
  permissions text[] NOT NULL DEFAULT '{}',
  requires_mfa boolean NOT NULL DEFAULT false,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (permission_group_id, role),
  CONSTRAINT gcr_role_format_chk CHECK (role ~ '^[a-z][a-z0-9-]*$')
);

-- Invitations
CREATE TABLE profiles.group_invite_links (
  id uuid PRIMARY KEY DEFAULT uuidv7(),
  permission_group_id uuid NOT NULL REFERENCES profiles.permission_groups(id) ON DELETE CASCADE,
  role text NOT NULL,
  invited_by uuid NOT NULL REFERENCES profiles.users(id) ON DELETE CASCADE,
  code_hash text NOT NULL UNIQUE,
  redeemed_at timestamptz,
  expires_at timestamptz,
  revoked_at timestamptz,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  CONSTRAINT gil_role_format_chk CHECK (role ~ '^[a-z][a-z0-9-]*$')
);
CREATE INDEX group_invite_links_group_idx
  ON profiles.group_invite_links (permission_group_id)
  WHERE revoked_at IS NULL;
CREATE INDEX group_invite_links_terminal_idx
  ON profiles.group_invite_links (LEAST(redeemed_at, revoked_at, expires_at), id);

CREATE TABLE profiles.account_registration_invites (
  id uuid PRIMARY KEY DEFAULT uuidv7(),
  email public.citext NOT NULL,
  invited_by uuid NOT NULL REFERENCES profiles.users(id) ON DELETE CASCADE,
  code_hash text NOT NULL UNIQUE,
  expires_at timestamptz NOT NULL,
  revoked_at timestamptz,
  consumed_at timestamptz,
  consumed_by uuid REFERENCES profiles.users(id) ON DELETE SET NULL,
  permission_group_id uuid REFERENCES profiles.permission_groups(id) ON DELETE CASCADE,
  role text,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  CONSTRAINT ari_role_format_chk CHECK (role IS NULL OR role ~ '^[a-z][a-z0-9-]*$'),
  CONSTRAINT ari_group_role_pairing_chk CHECK ((permission_group_id IS NULL) = (role IS NULL))
);
CREATE INDEX account_registration_invites_email_idx
  ON profiles.account_registration_invites (email, expires_at)
  WHERE revoked_at IS NULL AND consumed_at IS NULL;
CREATE INDEX account_registration_invites_terminal_idx
  ON profiles.account_registration_invites (LEAST(consumed_at, revoked_at, expires_at), id);

-- API keys
CREATE TABLE profiles.api_keys (
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
CREATE INDEX api_keys_group_idx
  ON profiles.api_keys (permission_group_id);
CREATE INDEX api_keys_terminal_idx
  ON profiles.api_keys (LEAST(revoked_at, expires_at), id);
COMMENT ON COLUMN profiles.api_keys.role IS
  'The single catalog/custom role this API key holds within its permission-group.';

-- Security events
CREATE TABLE profiles.session_events (
    id          bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    occurred_at timestamptz NOT NULL,
    issuer      text NOT NULL,
    user_id     text NOT NULL,
    session_id  text NOT NULL,
    event       text NOT NULL,
    method      text,
    reason      text,
    ip_addr     text,
    user_agent  text
);

CREATE INDEX session_events_user_occurred_idx
    ON profiles.session_events (user_id, occurred_at DESC);

CREATE INDEX session_events_occurred_idx
    ON profiles.session_events (occurred_at);

-- Signed documents
CREATE TABLE profiles.signed_documents (
  digest         text PRIMARY KEY,
  document_type  text NOT NULL,
  compact_jws    text NOT NULL,
  signed_payload bytea NOT NULL,
  created_at     timestamptz NOT NULL DEFAULT now(),
  updated_at     timestamptz NOT NULL DEFAULT now()
);

COMMENT ON TABLE profiles.signed_documents IS
  'AuthKit-published immutable signed documents (ak#260), served at /.well-known/authkit/documents/{digest}. Digest = sha256 over signed_payload; compact_jws may be re-signed on key rotation, payload/type never change.';

-- Native device credentials
CREATE TABLE profiles.user_device_keys (
  id           uuid PRIMARY KEY DEFAULT uuidv7(),
  user_id      uuid NOT NULL REFERENCES profiles.users(id) ON DELETE CASCADE,
  public_key   bytea NOT NULL UNIQUE,
  label        text,
  created_at   timestamptz NOT NULL DEFAULT now(),
  last_used_at timestamptz,
  revoked_at   timestamptz,
  CONSTRAINT user_device_keys_public_key_length_chk CHECK (octet_length(public_key) = 32),
  CONSTRAINT user_device_keys_label_length_chk CHECK (label IS NULL OR char_length(label) <= 128)
);

CREATE INDEX user_device_keys_user_active_idx
  ON profiles.user_device_keys (user_id)
  WHERE revoked_at IS NULL;

COMMENT ON TABLE profiles.user_device_keys IS
  'Ed25519 public keys for native clients. Revoked rows remain tombstones and cannot be re-enrolled.';

COMMENT ON COLUMN profiles.users.avatar_url IS 'Host-supplied avatar URL/key string; blob storage is host-owned';

-- Refresh-token custody
CREATE TABLE profiles.refresh_token_history (
    token_hash bytea PRIMARY KEY,
    session_id uuid NOT NULL REFERENCES profiles.refresh_sessions(id) ON DELETE CASCADE,
    consumed_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX refresh_token_history_session_idx
    ON profiles.refresh_token_history (session_id);

COMMENT ON COLUMN profiles.refresh_sessions.previous_rotated_at IS
  'When the most recent predecessor rotated. Bounds the rotation grace window.';

COMMENT ON COLUMN profiles.refresh_sessions.previous_successor_sealed IS
  'Successor refresh token, XOR-sealed under SHA-256(predecessor || domain separator). Readable only by a caller holding the predecessor token; the database alone cannot unseal it (ak#274).';

CREATE INDEX refresh_sessions_dead_idx
  ON profiles.refresh_sessions (id)
  WHERE revoked_at IS NOT NULL;
CREATE INDEX refresh_sessions_expires_idx
  ON profiles.refresh_sessions (expires_at)
  WHERE revoked_at IS NULL AND expires_at IS NOT NULL;

-- Canonical names and retained aliases
CREATE TABLE profiles.name_claims (
  owner_kind text NOT NULL CHECK (owner_kind IN ('user', 'group')),
  persona text NOT NULL,
  name text NOT NULL CHECK (name = lower(name) AND name <> ''),
  owner_id uuid NOT NULL,
  canonical boolean NOT NULL,
  expires_at timestamptz,
  PRIMARY KEY (owner_kind, persona, name),
  CHECK ((owner_kind = 'user' AND persona = '') OR (owner_kind = 'group' AND persona <> '')),
  CHECK (NOT canonical OR expires_at IS NULL)
);
CREATE UNIQUE INDEX name_claims_canonical_owner ON profiles.name_claims(owner_kind, owner_id) WHERE canonical;
CREATE INDEX name_claims_owner ON profiles.name_claims(owner_kind, owner_id);
CREATE INDEX name_claims_expiry ON profiles.name_claims(expires_at) WHERE NOT canonical AND expires_at IS NOT NULL;
CREATE FUNCTION profiles.lock_name_claims(kind text, scope text, handles text[]) RETURNS void LANGUAGE plpgsql AS $$
DECLARE stripe integer;
BEGIN
 FOR stripe IN SELECT DISTINCT (hashtextextended(kind || ':' || scope || ':' || lower(handle),631335) & 255)::integer
  FROM unnest(handles) AS handle WHERE COALESCE(handle,'')<>'' ORDER BY 1
 LOOP
  PERFORM pg_advisory_xact_lock(631335,stripe);
 END LOOP;
END;
$$;

CREATE FUNCTION profiles.claim_canonical_name(kind text, scope text, handle text, owner uuid, at_time timestamptz)
RETURNS void LANGUAGE plpgsql AS $$
BEGIN
 IF COALESCE(handle, '') = '' THEN RETURN; END IF;
 PERFORM profiles.lock_name_claims(kind, scope, ARRAY[handle]);
 INSERT INTO profiles.name_claims(owner_kind, persona, name, owner_id, canonical)
 VALUES (kind, scope, lower(handle), owner, true)
 ON CONFLICT (owner_kind, persona, name) DO UPDATE
 SET owner_id = EXCLUDED.owner_id, canonical = true, expires_at = NULL
 WHERE name_claims.owner_id = owner
    OR (NOT name_claims.canonical AND name_claims.expires_at <= at_time);
 IF NOT FOUND THEN
  RAISE EXCEPTION 'name is unavailable' USING ERRCODE = '23505', CONSTRAINT = 'name_claims_pkey';
 END IF;
END;
$$;

CREATE FUNCTION profiles.enforce_canonical_name_claim() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE kind text := TG_ARGV[0]; scope text; handle text; previous text;
BEGIN
 IF TG_OP='UPDATE' AND NEW.id <> OLD.id THEN RAISE EXCEPTION 'identity UUID is immutable' USING ERRCODE='23514'; END IF;
 IF kind = 'user' THEN
  scope := '';
  IF TG_OP = 'DELETE' THEN handle := OLD.username::text; ELSE handle := NEW.username::text; END IF;
  IF TG_OP = 'UPDATE' THEN previous := OLD.username::text; END IF;
 ELSE
  IF TG_OP = 'DELETE' THEN scope := OLD.persona; handle := OLD.instance_slug;
  ELSE scope := NEW.persona; handle := NEW.instance_slug; END IF;
  IF TG_OP = 'UPDATE' THEN
   previous := OLD.instance_slug;
   IF NEW.persona <> OLD.persona THEN RAISE EXCEPTION 'group persona is immutable' USING ERRCODE = '23514'; END IF;
  END IF;
 END IF;
 IF TG_OP = 'DELETE' THEN
  -- Raw deletion keeps existing canonical-release semantics. The explicit group
  -- lifecycle primitive first turns the canonical claim into a permanent alias
  -- when reservation is requested. Earlier rename aliases always survive.
  DELETE FROM profiles.name_claims WHERE owner_kind=kind AND owner_id=OLD.id AND canonical;
  RETURN OLD;
 END IF;
 IF TG_OP = 'INSERT' THEN
  PERFORM profiles.claim_canonical_name(kind, scope, handle, NEW.id, clock_timestamp());
 ELSIF lower(COALESCE(handle,'')) <> lower(COALESCE(previous,'')) THEN
  IF COALESCE(handle,'') = '' OR NOT EXISTS (
   SELECT 1 FROM profiles.name_claims WHERE owner_kind = kind AND persona = scope
    AND name = lower(handle) AND owner_id = NEW.id AND canonical
  ) THEN RAISE EXCEPTION 'rename requires an atomic name claim' USING ERRCODE = '23514'; END IF;
 END IF;
 RETURN NEW;
END;
$$;
CREATE TRIGGER users_name_claim AFTER INSERT OR UPDATE OF id, username OR DELETE ON profiles.users
 FOR EACH ROW EXECUTE FUNCTION profiles.enforce_canonical_name_claim('user');
CREATE TRIGGER groups_name_claim AFTER INSERT OR UPDATE OF id, instance_slug, persona OR DELETE ON profiles.permission_groups
 FOR EACH ROW EXECUTE FUNCTION profiles.enforce_canonical_name_claim('group');

CREATE FUNCTION profiles.invalidate_recovery_grants() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  IF ROW(NEW.email, NEW.phone_number, NEW.email_verified, NEW.phone_verified,
         NEW.banned_at, NEW.banned_until, NEW.deleted_at, NEW.metadata->'reserved')
     IS DISTINCT FROM
     ROW(OLD.email, OLD.phone_number, OLD.email_verified, OLD.phone_verified,
         OLD.banned_at, OLD.banned_until, OLD.deleted_at, OLD.metadata->'reserved') THEN
    NEW.credential_version := OLD.credential_version + 1;
  END IF;
  RETURN NEW;
END;
$$;
CREATE TRIGGER invalidate_recovery_grants
BEFORE UPDATE ON profiles.users
FOR EACH ROW EXECUTE FUNCTION profiles.invalidate_recovery_grants();
