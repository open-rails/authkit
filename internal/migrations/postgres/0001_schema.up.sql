-- AuthKit's PostgreSQL 18+ schema. A table comes before every table that
-- references it and is followed by its constraints, indexes, comments,
-- functions and triggers. The migration is transactional and never drops or
-- adopts existing AuthKit relations.
DO $$
BEGIN
  IF EXISTS (
    SELECT 1 FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
    WHERE n.nspname = current_schema() AND c.relname IN (
      'account_deletion_deliveries',
      'account_deletions',
      'account_delivery_fleets',
      'account_events',
      'account_registration_invites',
      'api_keys',
      'bootstrap_applies',
      'ephemeral_kv',
      'group_invite_links',
      'group_remote_application_roles',
      'group_user_roles',
      'mfa_factors',
      'mfa_settings',
      'name_claims',
      'permission_groups',
      'refresh_sessions',
      'refresh_token_history',
      'remote_applications',
      'role_catalogs',
      'session_events',
      'usable_users',
      'user_device_keys',
      'user_passkey_handles',
      'user_passkeys',
      'user_passwords',
      'user_providers',
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

-- Bind function lookups to migratekit's target schema, not a host connection.
-- pg_catalog remains implicitly first; explicit pg_temp keeps temporary tables
-- from shadowing AuthKit relations inside the captured function search path.
SELECT set_config('search_path', format('%I, public, pg_temp', current_schema()), true);

CREATE EXTENSION IF NOT EXISTS citext WITH SCHEMA public;
-- The user directory's search: trigram indexes serve substring matches.
CREATE EXTENSION IF NOT EXISTS pg_trgm WITH SCHEMA public;


-- Tenants: canonical business identities. Every account, tenant group,
-- invitation, deletion and SCIM target belongs to exactly one.
CREATE TABLE tenants (
  id uuid PRIMARY KEY,
  created_at timestamptz NOT NULL DEFAULT now(),
  slug text NOT NULL,
  slug_changed_at timestamptz,
  CONSTRAINT tenants_nonzero CHECK (id <> '00000000-0000-0000-0000-000000000000'::uuid),
  CONSTRAINT tenants_slug_format CHECK (slug ~ '^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$')
);
CREATE UNIQUE INDEX tenants_slug_key ON tenants(slug);
COMMENT ON TABLE tenants IS 'Canonical business identities shared with ContentKit; accounts of different tenants are independent.';
COMMENT ON COLUMN tenants.slug IS 'The tenant''s public name: unique, renamable, and never equal to another tenant''s unexpired former name (tenant_slug_aliases). Never a key, scope, claim or storage path; those use id.';
COMMENT ON COLUMN tenants.slug_changed_at IS 'When the tenant was last renamed; NULL if never.';

CREATE TABLE tenant_slug_aliases (
  slug text NOT NULL,
  tenant_id uuid NOT NULL,
  expires_at timestamptz,
  created_at timestamptz NOT NULL DEFAULT now(),
  CONSTRAINT tenant_slug_aliases_pkey PRIMARY KEY (slug),
  CONSTRAINT tenant_slug_aliases_tenant_id_fkey FOREIGN KEY (tenant_id) REFERENCES tenants(id) ON DELETE RESTRICT
);
CREATE INDEX tenant_slug_aliases_tenant_id_idx ON tenant_slug_aliases(tenant_id);
COMMENT ON TABLE tenant_slug_aliases IS 'Former tenant names. An unexpired alias forwards to its tenant and blocks every other claim of the name; expires_at NULL keeps it forever. Written by a rename, removed when its tenant takes the name back or when it expires and is claimed.';

-- One name namespace across live names and aliases. Claims serialize per name
-- on a transaction lock, so a rename's alias and a concurrent claim of the same
-- name cannot both win.
CREATE FUNCTION guard_tenant_name() RETURNS trigger
LANGUAGE plpgsql SET search_path FROM CURRENT AS $$
BEGIN
  IF TG_OP = 'UPDATE' THEN
    IF OLD.slug = NEW.slug THEN
      RETURN NEW;
    END IF;
    PERFORM pg_advisory_xact_lock(471, hashtext(least(OLD.slug, NEW.slug)));
    PERFORM pg_advisory_xact_lock(471, hashtext(greatest(OLD.slug, NEW.slug)));
  ELSE
    PERFORM pg_advisory_xact_lock(471, hashtext(NEW.slug));
  END IF;
  DELETE FROM tenant_slug_aliases
   WHERE slug = NEW.slug AND (tenant_id = NEW.id OR expires_at <= now());
  IF EXISTS (SELECT 1 FROM tenant_slug_aliases WHERE slug = NEW.slug) THEN
    RAISE EXCEPTION 'tenant name % is another tenant''s former name', NEW.slug
      USING ERRCODE = '23505', CONSTRAINT = 'tenant_slug_aliases_pkey';
  END IF;
  RETURN NEW;
END;
$$;
COMMENT ON FUNCTION guard_tenant_name() IS 'A tenant name is never another tenant''s unexpired former name. Raises 23505 on tenant_slug_aliases_pkey.';
REVOKE ALL ON FUNCTION guard_tenant_name() FROM PUBLIC;
CREATE TRIGGER guard_tenant_name BEFORE INSERT OR UPDATE OF slug ON tenants
  FOR EACH ROW EXECUTE FUNCTION guard_tenant_name();

-- Tenant ownership is immutable on every row that records it.
CREATE FUNCTION preserve_tenant_ownership() RETURNS trigger
LANGUAGE plpgsql SET search_path FROM CURRENT AS $$
BEGIN
 IF NEW.tenant_id IS DISTINCT FROM OLD.tenant_id THEN
  RAISE EXCEPTION 'tenant ownership is immutable' USING ERRCODE='23514';
 END IF;
 RETURN NEW;
END;
$$;


-- Accounts
CREATE TABLE users (
  id uuid PRIMARY KEY DEFAULT uuidv7(),
  email public.citext,
  username public.citext,
  email_verified boolean NOT NULL DEFAULT false,
  phone_number text,
  phone_verified boolean NOT NULL DEFAULT false,
  banned_at timestamptz,
  banned_until timestamptz,
  ban_reason text,
  banned_by uuid REFERENCES users(id) ON DELETE SET NULL,
  deleted_at timestamptz,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  last_login timestamptz,
  preferred_language text,
  last_renamed_at timestamptz,
  credential_version bigint NOT NULL DEFAULT 1 CHECK (credential_version > 0),
  public_metadata jsonb NOT NULL DEFAULT '{}'::jsonb
    CONSTRAINT users_public_metadata_object CHECK (jsonb_typeof(public_metadata) = 'object'),
  profile_updated_at timestamptz NOT NULL DEFAULT now(),
  tenant_id uuid NOT NULL REFERENCES tenants(id),
  mfa_required boolean NOT NULL DEFAULT false,
  -- A ban exists exactly while banned_at is set.
  CONSTRAINT users_ban_chk CHECK (banned_at IS NOT NULL OR num_nulls(banned_until, ban_reason, banned_by) = 3),
  CONSTRAINT users_tenant_id_id_key UNIQUE (tenant_id, id)
);
-- The account identifier namespace belongs to one business, not the shared DB.
CREATE UNIQUE INDEX users_tenant_username_uidx ON users(tenant_id,username) WHERE username IS NOT NULL;
CREATE UNIQUE INDEX users_tenant_email_uidx ON users(tenant_id,email) WHERE email IS NOT NULL;
CREATE UNIQUE INDEX users_tenant_phone_uidx ON users(tenant_id,phone_number) WHERE phone_number IS NOT NULL;
CREATE INDEX users_tenant_created_idx ON users(tenant_id,created_at,id);
CREATE INDEX users_admin_created_idx
  ON users (created_at DESC, id)
  WHERE deleted_at IS NULL;
CREATE INDEX users_admin_last_login_idx
  ON users (last_login DESC, id)
  WHERE deleted_at IS NULL;
CREATE INDEX users_admin_username_idx
  ON users (username, id)
  WHERE deleted_at IS NULL;
CREATE INDEX users_admin_email_idx
  ON users (email, id)
  WHERE deleted_at IS NULL;
CREATE INDEX users_deleted_at_idx
  ON users (deleted_at, id)
  WHERE deleted_at IS NOT NULL;
CREATE INDEX users_admin_banned_idx
  ON users (banned_at, id)
  WHERE deleted_at IS NULL AND banned_at IS NOT NULL;
-- A purge finds the bans its account imposed.
CREATE INDEX users_banned_by_idx
  ON users (banned_by)
  WHERE banned_by IS NOT NULL;
-- The user directory's search (ListUsers): username, email and phone match by
-- substring; the columns are indexed as text, so the search casts citext to
-- text (citext's own ILIKE is no trigram operator).
CREATE INDEX users_username_trgm_idx
  ON users USING gin (username public.gin_trgm_ops);
CREATE INDEX users_email_trgm_idx
  ON users USING gin (email public.gin_trgm_ops);
CREATE INDEX users_phone_number_trgm_idx
  ON users USING gin (phone_number public.gin_trgm_ops);
COMMENT ON COLUMN users.phone_number IS 'E.164 format phone number (e.g. +14155551234)';
COMMENT ON COLUMN users.phone_verified IS 'Whether the phone number has been verified via SMS code';
COMMENT ON COLUMN users.banned_at IS 'When the user was banned';
COMMENT ON COLUMN users.banned_until IS 'When a temporary ban expires (NULL for permanent)';
COMMENT ON COLUMN users.ban_reason IS 'Reason for ban';
COMMENT ON COLUMN users.banned_by IS 'User ID of admin who imposed ban';
COMMENT ON COLUMN users.preferred_language IS 'User communication/auth language, e.g. en, es, de, ko, zh';
COMMENT ON COLUMN users.public_metadata IS 'Host-written application data anyone may read';
COMMENT ON COLUMN users.profile_updated_at IS 'When email, its verification, username, deletion or ban last changed';
COMMENT ON COLUMN users.mfa_required IS 'Administrator-required MFA; enrollment may be completed after the policy is set';

-- A change to how the account is reached or whether it may sign in bumps
-- credential_version, voiding proofs issued against the old one.
CREATE FUNCTION invalidate_recovery_grants() RETURNS trigger
LANGUAGE plpgsql SET search_path FROM CURRENT AS $$
BEGIN
  IF ROW(NEW.email, NEW.phone_number, NEW.email_verified, NEW.phone_verified,
         NEW.banned_at, NEW.banned_until, NEW.deleted_at)
     IS DISTINCT FROM
     ROW(OLD.email, OLD.phone_number, OLD.email_verified, OLD.phone_verified,
         OLD.banned_at, OLD.banned_until, OLD.deleted_at) THEN
    NEW.credential_version := OLD.credential_version + 1;
  END IF;
  RETURN NEW;
END;
$$;
CREATE TRIGGER invalidate_recovery_grants
  BEFORE UPDATE ON users
  FOR EACH ROW EXECUTE FUNCTION invalidate_recovery_grants();

-- The one test of a ban in force: an expired temporary ban is no ban. It
-- inlines, so the partial ban index still serves it.
CREATE FUNCTION ban_in_force(banned_at timestamptz, banned_until timestamptz) RETURNS boolean
LANGUAGE sql STABLE
RETURN banned_at IS NOT NULL AND (banned_until IS NULL OR banned_until > statement_timestamp());

-- The one definition of a usable account: not deleted and no ban in force.
-- Credential issuers, registrars and group owners count only while usable.
CREATE VIEW usable_users AS
SELECT id FROM users
WHERE deleted_at IS NULL AND NOT ban_in_force(banned_at, banned_until);

-- Usernames: one canonical claim per account plus retained aliases, per
-- tenant. A deleted account's username stays reserved forever.
CREATE TABLE name_claims (
  name text NOT NULL CHECK (name = lower(name) AND name <> ''),
  owner_id uuid NOT NULL,
  canonical boolean NOT NULL,
  expires_at timestamptz,
  tenant_id uuid NOT NULL REFERENCES tenants(id),
  PRIMARY KEY (tenant_id, name),
  CONSTRAINT name_claims_check1 CHECK (NOT canonical OR expires_at IS NULL)
);
CREATE UNIQUE INDEX name_claims_canonical_owner ON name_claims (owner_id) WHERE canonical;
CREATE INDEX name_claims_owner ON name_claims (owner_id);
CREATE INDEX name_claims_expiry ON name_claims (expires_at) WHERE NOT canonical AND expires_at IS NOT NULL;

-- A name may be claimed before its account is inserted in the same transaction.
-- Purged accounts retain noncanonical name tombstones, so a strict FK would be
-- wrong: validate a live owner if present, and require one for canonical claims.
CREATE FUNCTION enforce_name_claim_tenant() RETURNS trigger
LANGUAGE plpgsql SET search_path FROM CURRENT AS $$
DECLARE claim name_claims%ROWTYPE; owner_tenant uuid;
BEGIN
 SELECT * INTO claim FROM name_claims WHERE tenant_id=NEW.tenant_id AND name=NEW.name;
 IF NOT FOUND THEN RETURN NULL; END IF;
 SELECT tenant_id INTO owner_tenant FROM users WHERE id=claim.owner_id;
 IF (FOUND AND owner_tenant<>claim.tenant_id) OR (NOT FOUND AND claim.canonical) THEN
  RAISE EXCEPTION 'name claim owner must belong to its tenant' USING ERRCODE='23514';
 END IF;
 RETURN NULL;
END;
$$;
CREATE CONSTRAINT TRIGGER name_claims_tenant_owner
AFTER INSERT OR UPDATE ON name_claims DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW EXECUTE FUNCTION enforce_name_claim_tenant();
CREATE TRIGGER name_claims_tenant_immutable BEFORE UPDATE OF tenant_id ON name_claims FOR EACH ROW EXECUTE FUNCTION preserve_tenant_ownership();

CREATE FUNCTION lock_name_claims(tenant uuid, handles text[]) RETURNS void
LANGUAGE plpgsql SET search_path FROM CURRENT AS $$
DECLARE stripe integer;
BEGIN
 IF tenant IS NULL THEN RAISE EXCEPTION 'tenant required' USING ERRCODE='23502'; END IF;
 FOR stripe IN SELECT DISTINCT (hashtextextended(tenant::text || ':user::' || lower(handle),631335) & 255)::integer
  FROM unnest(handles) AS handle WHERE COALESCE(handle,'')<>'' ORDER BY 1
 LOOP
  PERFORM pg_advisory_xact_lock(631335,stripe);
 END LOOP;
END;
$$;

CREATE FUNCTION claim_canonical_name(tenant uuid, handle text, owner uuid, at_time timestamptz) RETURNS void
LANGUAGE plpgsql SET search_path FROM CURRENT AS $$
BEGIN
 IF COALESCE(handle, '') = '' THEN RETURN; END IF;
 PERFORM lock_name_claims(tenant, ARRAY[handle]);
 INSERT INTO name_claims(tenant_id,name,owner_id,canonical)
 VALUES (tenant,lower(handle),owner,true)
 ON CONFLICT(tenant_id,name) DO UPDATE
 SET owner_id=EXCLUDED.owner_id, canonical=true, expires_at=NULL
 WHERE name_claims.owner_id=owner OR (NOT name_claims.canonical AND name_claims.expires_at<=at_time);
 IF NOT FOUND THEN
  RAISE EXCEPTION 'name is unavailable' USING ERRCODE='23505', CONSTRAINT='name_claims_pkey';
 END IF;
END;
$$;

CREATE FUNCTION enforce_canonical_name_claim() RETURNS trigger
LANGUAGE plpgsql SET search_path FROM CURRENT AS $$
DECLARE handle text; previous text;
BEGIN
 IF TG_OP='UPDATE' AND (NEW.id<>OLD.id OR NEW.tenant_id<>OLD.tenant_id) THEN
  RAISE EXCEPTION 'account and tenant identity are immutable' USING ERRCODE='23514';
 END IF;
 IF TG_OP='DELETE' THEN
  UPDATE name_claims SET canonical=false, expires_at=NULL WHERE tenant_id=OLD.tenant_id AND owner_id=OLD.id AND canonical;
  RETURN OLD;
 END IF;
 handle := NEW.username::text;
 IF TG_OP='INSERT' THEN
  PERFORM claim_canonical_name(NEW.tenant_id,handle,NEW.id,clock_timestamp());
 ELSE
  previous := OLD.username::text;
  IF lower(COALESCE(handle,''))<>lower(COALESCE(previous,'')) AND (COALESCE(handle,'')='' OR NOT EXISTS(
   SELECT 1 FROM name_claims WHERE tenant_id=NEW.tenant_id AND name=lower(handle) AND owner_id=NEW.id AND canonical
  )) THEN RAISE EXCEPTION 'rename requires an atomic name claim' USING ERRCODE='23514'; END IF;
 END IF;
 RETURN NEW;
END;
$$;
CREATE TRIGGER users_name_claim AFTER INSERT OR UPDATE OF id,tenant_id,username OR DELETE ON users
 FOR EACH ROW EXECUTE FUNCTION enforce_canonical_name_claim();


-- Credentials
CREATE TABLE user_passwords (
  user_id uuid PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
  password_hash text NOT NULL,
  hash_algo text NOT NULL DEFAULT 'argon2id',
  password_updated_at timestamptz NOT NULL DEFAULT now()
);

-- A linked sign-in. The directory's search matches it exactly on its subject
-- (a wallet address, a provider's user id), provider email or provider
-- username.
CREATE TABLE user_providers (
  id uuid PRIMARY KEY DEFAULT uuidv7(),
  user_id uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  issuer text NOT NULL,
  provider_slug text,
  subject text NOT NULL,
  email_at_provider text,
  profile jsonb,
  created_at timestamptz NOT NULL DEFAULT now(),
  verified_at timestamptz DEFAULT now(),
  tenant_id uuid NOT NULL,
  UNIQUE (user_id, issuer),
  CONSTRAINT user_providers_tenant_user_fk
    FOREIGN KEY (tenant_id, user_id) REFERENCES users(tenant_id, id) ON DELETE CASCADE
);
CREATE UNIQUE INDEX user_providers_tenant_issuer_subject_key ON user_providers(tenant_id,issuer,subject);
CREATE INDEX user_providers_user_id_provider_slug_idx
  ON user_providers (user_id, provider_slug);
CREATE INDEX user_providers_subject_idx
  ON user_providers (subject);
CREATE INDEX user_providers_email_lower_idx
  ON user_providers (lower(email_at_provider));
CREATE INDEX user_providers_username_lower_idx
  ON user_providers (lower(profile->>'username'));

CREATE TABLE user_passkey_handles (
  user_id uuid PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
  user_handle bytea NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now()
);
CREATE UNIQUE INDEX uniq_user_passkey_handles_handle
  ON user_passkey_handles (user_handle);

CREATE TABLE user_passkeys (
  id uuid PRIMARY KEY DEFAULT uuidv7(),
  user_id uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  rpid varchar(512) NOT NULL,
  credential_id bytea NOT NULL,
  public_key bytea NOT NULL,
  sign_count bigint NOT NULL DEFAULT 0,
  clone_warning boolean NOT NULL DEFAULT false,
  aaguid bytea,
  transports text[] NOT NULL DEFAULT '{}',
  authenticator_attachment text NOT NULL DEFAULT '',
  flags bytea NOT NULL DEFAULT '\x00',
  attestation_type text NOT NULL DEFAULT '',
  attestation_fmt text NOT NULL DEFAULT '',
  label text,
  created_at timestamptz NOT NULL DEFAULT now(),
  last_used_at timestamptz
);
CREATE UNIQUE INDEX uniq_user_passkeys_rpid_credential
  ON user_passkeys (rpid, credential_id);
CREATE INDEX user_passkeys_user_idx
  ON user_passkeys (user_id);

-- A device key stands in for a second factor only when its enrollment proved
-- one (mfa_proven_at).
CREATE TABLE user_device_keys (
  id uuid PRIMARY KEY DEFAULT uuidv7(),
  user_id uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  public_key bytea NOT NULL UNIQUE,
  label text,
  created_at timestamptz NOT NULL DEFAULT now(),
  last_used_at timestamptz,
  revoked_at timestamptz,
  mfa_proven_at timestamptz,
  CONSTRAINT user_device_keys_public_key_length_chk CHECK (octet_length(public_key) = 32),
  CONSTRAINT user_device_keys_label_length_chk CHECK (label IS NULL OR char_length(label) <= 128)
);
CREATE INDEX user_device_keys_user_idx
  ON user_device_keys (user_id);
COMMENT ON TABLE user_device_keys IS
  'Ed25519 public keys for native clients. Revoked rows remain tombstones and cannot be re-enrolled.';

-- 2FA is on while the account has a factor.
CREATE TABLE mfa_settings (
  user_id uuid PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
  backup_codes text[],
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now()
);
COMMENT ON TABLE mfa_settings IS 'Account recovery-code hashes; retained while a code factor or passkey exists. This row does not enable MFA.';
COMMENT ON COLUMN mfa_settings.backup_codes IS 'Hashed backup codes for account recovery';

-- An email or SMS factor is bound to the address its setup code proved:
-- changing the account's contact never redirects its codes.
CREATE TABLE mfa_factors (
  id uuid PRIMARY KEY DEFAULT uuidv7(),
  user_id uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  method varchar(10) NOT NULL CHECK (method IN ('email', 'sms', 'totp')),
  phone_number varchar(20),
  totp_secret bytea,
  last_totp_step bigint,
  is_default boolean NOT NULL DEFAULT false,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  email text,
  CONSTRAINT mfa_factor_phone_required_for_sms CHECK (
    (method = 'sms' AND phone_number IS NOT NULL) OR method <> 'sms'
  ),
  CONSTRAINT mfa_factor_totp_secret_required CHECK (
    (method = 'totp' AND totp_secret IS NOT NULL) OR method <> 'totp'
  )
);
CREATE UNIQUE INDEX uniq_mfa_factors_default
  ON mfa_factors (user_id)
  WHERE is_default = true;
CREATE UNIQUE INDEX uniq_mfa_factors_user_method
  ON mfa_factors (user_id, method);
COMMENT ON TABLE mfa_factors IS 'Enrolled 2FA factors per user (hard-deleted on removal); backup codes remain user-scoped on mfa_settings';
COMMENT ON COLUMN mfa_factors.is_default IS 'Default factor AuthKit challenges first when 2FA is required';

-- Each version of a document a user accepted, append-only.
CREATE TABLE user_agreements (
  user_id uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  key text NOT NULL CONSTRAINT ua_key_chk CHECK (key ~ '^[a-z0-9][a-z0-9_-]{0,63}$'),
  version text NOT NULL CONSTRAINT ua_version_chk CHECK (length(version) BETWEEN 1 AND 64),
  accepted_at timestamptz NOT NULL DEFAULT now(),
  channel text NOT NULL CONSTRAINT ua_channel_chk CHECK (channel IN ('registration', 'account', 'host')),
  ip_addr inet,
  user_agent text,
  PRIMARY KEY (user_id, key, version)
);
COMMENT ON TABLE user_agreements IS
  'Each version of a declared document (Config.Agreements) a user accepted: when, where and from which client. Never updated; purged with the account.';


-- Sessions
CREATE TABLE refresh_sessions (
  id uuid PRIMARY KEY DEFAULT uuidv7(),
  user_id uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  issuer text NOT NULL,
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
  previous_rotated_at timestamptz,
  -- A sensitive action on an account with a second factor needs that factor
  -- within the freshness window; a password re-auth never refreshes it.
  mfa_authenticated_at timestamptz,
  -- A sign-in session bound to a DPoP key (RFC 9449 §5): its access tokens
  -- carry cnf.jkt, and each refresh proves the same key.
  dpop_jkt text
    CONSTRAINT refresh_sessions_dpop_jkt_chk CHECK (dpop_jkt IS NULL OR dpop_jkt ~ '^[A-Za-z0-9_-]{43}$')
);
CREATE UNIQUE INDEX refresh_sessions_current_hash_active
  ON refresh_sessions (current_token_hash)
  WHERE revoked_at IS NULL;
CREATE INDEX refresh_sessions_user_idx
  ON refresh_sessions (user_id, issuer, last_used_at);
CREATE INDEX refresh_sessions_dead_idx
  ON refresh_sessions (id)
  WHERE revoked_at IS NOT NULL;
CREATE INDEX refresh_sessions_expires_idx
  ON refresh_sessions (expires_at)
  WHERE revoked_at IS NULL AND expires_at IS NOT NULL;
COMMENT ON COLUMN refresh_sessions.previous_rotated_at IS
  'When the most recent predecessor rotated. Bounds the rotation grace window.';
COMMENT ON COLUMN refresh_sessions.previous_successor_sealed IS
  'Successor refresh token, XOR-sealed under SHA-256(predecessor || domain separator). Readable only by a caller holding the predecessor token; the database alone cannot unseal it (ak#274).';
COMMENT ON COLUMN refresh_sessions.dpop_jkt IS
  'The RFC 7638 thumbprint of the DPoP key the session is bound to; NULL for a bearer session.';

-- Rotation prunes a session's history older than 90 days (SessionRotate).
CREATE TABLE refresh_token_history (
  token_hash bytea PRIMARY KEY,
  session_id uuid NOT NULL REFERENCES refresh_sessions(id) ON DELETE CASCADE,
  consumed_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX refresh_token_history_session_idx
  ON refresh_token_history (session_id, consumed_at);

-- Sign-in history; a host's import is identified by its import_id.
CREATE TABLE session_events (
  id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  occurred_at timestamptz NOT NULL,
  issuer text NOT NULL,
  user_id text NOT NULL,
  session_id text NOT NULL,
  event text NOT NULL,
  method text,
  reason text,
  ip_addr text,
  user_agent text,
  import_id text
);
CREATE INDEX session_events_user_occurred_idx
  ON session_events (user_id, occurred_at DESC);
CREATE INDEX session_events_occurred_idx
  ON session_events (occurred_at);
CREATE UNIQUE INDEX session_events_import_id_idx
  ON session_events (user_id, import_id) WHERE import_id IS NOT NULL;


-- Permission groups: root plus flat persona groups. The entity a group guards
-- lives in the host app, keyed by group id. Root is global; every other group
-- belongs to one tenant, and a tenant's own group has the tenant's id.
CREATE TABLE permission_groups (
  id uuid PRIMARY KEY DEFAULT uuidv7(),
  persona text NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  deleted_at timestamptz,
  tenant_id uuid REFERENCES tenants(id),
  CONSTRAINT pg_persona_format_chk CHECK (persona ~ '^[a-z][a-z0-9-]*$'),
  CONSTRAINT permission_groups_root_active CHECK (persona <> 'root' OR deleted_at IS NULL),
  CONSTRAINT permission_groups_tenant_scope_check
    CHECK ((persona = 'root' AND tenant_id IS NULL) OR (persona <> 'root' AND tenant_id IS NOT NULL)),
  CONSTRAINT permission_groups_tenant_identity_check
    CHECK (persona <> 'tenant' OR id=tenant_id)
);
CREATE UNIQUE INDEX permission_groups_singleton_root_uidx
  ON permission_groups ((persona = 'root'))
  WHERE persona = 'root';
CREATE INDEX permission_groups_persona_idx
  ON permission_groups (persona);
CREATE INDEX permission_groups_tenant_idx ON permission_groups(tenant_id,id);
COMMENT ON COLUMN permission_groups.deleted_at IS 'Retained inactive group state; the trusted host owns retention and purge.';

CREATE FUNCTION permission_group_identity_immutable() RETURNS trigger
LANGUAGE plpgsql SET search_path FROM CURRENT AS $$
BEGIN
 RAISE EXCEPTION 'a permission group''s id and persona are immutable' USING ERRCODE = '23514';
END;
$$;
CREATE TRIGGER permission_group_identity_immutable
  BEFORE UPDATE OF id, persona ON permission_groups
  FOR EACH ROW WHEN (NEW.id IS DISTINCT FROM OLD.id OR NEW.persona IS DISTINCT FROM OLD.persona)
  EXECUTE FUNCTION permission_group_identity_immutable();
CREATE TRIGGER permission_groups_tenant_immutable BEFORE UPDATE OF tenant_id ON permission_groups FOR EACH ROW EXECUTE FUNCTION preserve_tenant_ownership();

-- A deployment that names its first tenant (MigrationOptions.LegacyTenantID)
-- gets it with its canonical group.
DO $$
DECLARE named uuid := NULLIF(current_setting('authkit.legacy_tenant_id', true), '')::uuid;
BEGIN
  IF named IS NOT NULL THEN
    INSERT INTO tenants(id, slug) VALUES (named, 'tenant-' || replace(named::text, '-', ''));
    INSERT INTO permission_groups(id, persona, tenant_id) VALUES (named, 'tenant', named);
  END IF;
END;
$$;

-- A role has one text form everywhere: `<persona>:<name>`.
CREATE TABLE group_user_roles (
  permission_group_id uuid NOT NULL REFERENCES permission_groups(id) ON DELETE CASCADE,
  user_id uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  role text NOT NULL,
  PRIMARY KEY (permission_group_id, user_id),
  CONSTRAINT gur_role_format_chk CHECK (role ~ '^[a-z][a-z0-9-]*:[a-z][a-z0-9-]*$')
);
CREATE INDEX gur_user_idx
  ON group_user_roles (user_id);

-- A tenant role is assigned only to accounts owned by that business. Root
-- assignments remain global; no separate app-membership record is required.
CREATE FUNCTION enforce_group_user_tenant() RETURNS trigger
LANGUAGE plpgsql SET search_path FROM CURRENT AS $$
DECLARE owner uuid;
BEGIN
 IF NOT EXISTS(SELECT 1 FROM group_user_roles WHERE permission_group_id=NEW.permission_group_id AND user_id=NEW.user_id) THEN
  RETURN NULL;
 END IF;
 SELECT tenant_id INTO owner FROM permission_groups WHERE id=NEW.permission_group_id;
 IF owner IS NOT NULL AND NOT EXISTS(SELECT 1 FROM users WHERE id=NEW.user_id AND tenant_id=owner) THEN
  RAISE EXCEPTION 'group and account tenant must match' USING ERRCODE='23514';
 END IF;
 RETURN NULL;
END;
$$;
CREATE CONSTRAINT TRIGGER group_user_tenant_owner AFTER INSERT OR UPDATE ON group_user_roles
DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION enforce_group_user_tenant();

-- Roles groups define at run time, held only in that group. Their names
-- (`<persona>:custom-<name>`) never meet a declared role's.
CREATE TABLE group_custom_roles (
  permission_group_id uuid NOT NULL REFERENCES permission_groups(id) ON DELETE CASCADE,
  role text NOT NULL CONSTRAINT gcr_role_format_chk CHECK (role ~ '^[a-z][a-z0-9-]*:custom-[a-z][a-z0-9-]*$'),
  permissions text[] NOT NULL CONSTRAINT gcr_permissions_chk CHECK (cardinality(permissions) BETWEEN 1 AND 256),
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (permission_group_id, role)
);
COMMENT ON TABLE group_custom_roles IS
  'Roles groups define at run time: what each grants, read live on every check; deleting one first revokes it from every holder.';

-- Group credentials: remote applications, API keys, personal access tokens and
-- invitations. Each records the app that issued it (catalog_issuer), and only
-- that app's role catalog judges it. A NULL issuer is the operator.
CREATE TABLE remote_applications (
  id uuid PRIMARY KEY DEFAULT uuidv7(),
  issuer text NOT NULL UNIQUE,
  jwks_uri text NOT NULL DEFAULT '',
  mode text NOT NULL DEFAULT 'jwks',
  public_keys jsonb,
  enabled boolean NOT NULL DEFAULT true,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  permission_group_id uuid NOT NULL REFERENCES permission_groups(id) ON DELETE CASCADE,
  trust_root text NOT NULL DEFAULT 'manual',
  registered_by uuid REFERENCES users(id) ON DELETE SET NULL,
  catalog_issuer text,
  declared_by text,
  -- Maps the role names its tokens carry (RFC 9068 §2.2.3.1) to roles of its
  -- group.
  role_map jsonb
    CONSTRAINT remote_applications_role_map_chk CHECK (role_map IS NULL OR jsonb_typeof(role_map) = 'object'),
  private_network boolean NOT NULL DEFAULT false,
  CONSTRAINT remote_applications_trust_root_chk CHECK (trust_root IN ('manual', 'user')),
  CONSTRAINT remote_applications_mode_chk CHECK (mode IN ('jwks', 'static')),
  -- A jwks-mode application without a jwks_uri has its keys discovered from
  -- its issuer's metadata (RFC 8414).
  CONSTRAINT remote_applications_trust_source_xor CHECK (
    (mode = 'jwks' AND public_keys IS NULL)
    OR
    (mode = 'static' AND jwks_uri = '' AND public_keys IS NOT NULL
      AND jsonb_typeof(public_keys) = 'array' AND jsonb_array_length(public_keys) > 0)
  )
);
CREATE INDEX remote_applications_group_idx
  ON remote_applications (permission_group_id);
CREATE INDEX remote_applications_registered_by_idx
  ON remote_applications (registered_by);
COMMENT ON TABLE remote_applications IS
  'Registered applications: external systems that authenticate by signing JWTs verified against configured keys.';
COMMENT ON COLUMN remote_applications.permission_group_id IS
  'Required controlling permission-group. Authority comes from group_remote_application_roles on it and on root.';
COMMENT ON COLUMN remote_applications.trust_root IS
  'What changes the keys: manual (the system) | user (a credentials manager of the controlling group). Never the keypair alone.';
COMMENT ON COLUMN remote_applications.registered_by IS 'The user who supplied the keys of a group registration; NULL = the operator.';
COMMENT ON COLUMN remote_applications.catalog_issuer IS 'The Token.Issuer of the app its registrar registered it through; only its role catalog judges the application''s roles. NULL = every app does.';
COMMENT ON COLUMN remote_applications.declared_by IS
  'The Token.Issuer of the app whose Config.RemoteApplications declares it; NULL = registered through an operation.';
COMMENT ON COLUMN remote_applications.role_map IS
  'Role names its tokens carry (the roles claim) mapped to role texts of its group; NULL maps none.';
COMMENT ON COLUMN remote_applications.private_network IS
  'Whether its JWKS and metadata may be fetched from private or loopback addresses: true only for applications the host declared (configuration, DeclareRemoteApplications, the bootstrap manifest); false for any registered at run time.';

CREATE TABLE group_remote_application_roles (
  permission_group_id uuid NOT NULL REFERENCES permission_groups(id) ON DELETE CASCADE,
  remote_application_id uuid NOT NULL REFERENCES remote_applications(id) ON DELETE CASCADE,
  role text NOT NULL,
  PRIMARY KEY (permission_group_id, remote_application_id),
  CONSTRAINT grar_role_format_chk CHECK (role ~ '^[a-z][a-z0-9-]*:[a-z][a-z0-9-]*$')
);
CREATE INDEX grar_remote_application_idx
  ON group_remote_application_roles (remote_application_id);

-- A group's API keys belong to the group; their creator is audit information.
CREATE TABLE api_keys (
  id uuid PRIMARY KEY DEFAULT uuidv7(),
  permission_group_id uuid NOT NULL REFERENCES permission_groups(id) ON DELETE CASCADE,
  key_id text NOT NULL UNIQUE,
  secret_hash bytea NOT NULL,
  name text NOT NULL,
  created_by uuid REFERENCES users(id) ON DELETE SET NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  last_used_at timestamptz,
  expires_at timestamptz,
  revoked_at timestamptz,
  role text NOT NULL,
  catalog_issuer text,
  provisions_for uuid REFERENCES remote_applications(id) ON DELETE CASCADE,
  CONSTRAINT api_keys_name_len_chk CHECK (char_length(name) BETWEEN 1 AND 128),
  CONSTRAINT api_keys_role_format_chk CHECK (role ~ '^[a-z][a-z0-9-]*:[a-z][a-z0-9-]*$')
);
CREATE INDEX api_keys_group_idx
  ON api_keys (permission_group_id);
CREATE INDEX api_keys_created_by_idx
  ON api_keys (created_by);
CREATE INDEX api_keys_terminal_idx
  ON api_keys (LEAST(revoked_at, expires_at), id);
CREATE INDEX api_keys_provisions_for_idx ON api_keys (provisions_for) WHERE provisions_for IS NOT NULL;
COMMENT ON COLUMN api_keys.created_by IS 'Audit: creating user, or NULL for system issuance or a purged creator. Does not own the key.';
COMMENT ON COLUMN api_keys.role IS 'The one catalog role this API key holds in its permission group.';
COMMENT ON COLUMN api_keys.catalog_issuer IS 'The Token.Issuer of the app that issued the key; only its role catalog judges it. NULL = every app does.';
COMMENT ON COLUMN api_keys.provisions_for IS 'The remote application of the key''s group whose users the key provisions over SCIM; NULL for none.';

-- A personal token is a separate credential, bounded by a live user's
-- authority. It is never an organization key or an interactive sign-in.
CREATE TABLE personal_access_tokens (
    id uuid PRIMARY KEY DEFAULT uuidv7(),
    owner_user_id uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    permission_group_id uuid NOT NULL REFERENCES permission_groups(id) ON DELETE CASCADE,
    catalog_issuer text NOT NULL,
    lookup_id text NOT NULL UNIQUE,
    secret_hash bytea NOT NULL,
    name text NOT NULL CHECK (char_length(name) BETWEEN 1 AND 128),
    permissions text[] NOT NULL CHECK (cardinality(permissions) BETWEEN 1 AND 100),
    created_at timestamptz NOT NULL DEFAULT now(),
    last_used_at timestamptz,
    expires_at timestamptz NOT NULL,
    revoked_at timestamptz
);
CREATE INDEX personal_access_tokens_owner_idx ON personal_access_tokens(owner_user_id, catalog_issuer, id DESC);
CREATE INDEX personal_access_tokens_group_idx ON personal_access_tokens(permission_group_id);
CREATE INDEX personal_access_tokens_terminal_idx ON personal_access_tokens(LEAST(revoked_at, expires_at), id);

-- None outlives the user who issued it. Even a root-group invitation targets
-- one account directory; its operator may come from another tenant, so the
-- inviter is not an ownership fallback.
CREATE TABLE group_invite_links (
  id uuid PRIMARY KEY DEFAULT uuidv7(),
  permission_group_id uuid NOT NULL REFERENCES permission_groups(id) ON DELETE CASCADE,
  role text NOT NULL,
  invited_by uuid REFERENCES users(id) ON DELETE CASCADE,
  code_hash text NOT NULL UNIQUE,
  redeemed_at timestamptz,
  expires_at timestamptz,
  revoked_at timestamptz,
  created_at timestamptz NOT NULL DEFAULT now(),
  catalog_issuer text,
  tenant_id uuid NOT NULL REFERENCES tenants(id),
  CONSTRAINT gil_role_format_chk CHECK (role ~ '^[a-z][a-z0-9-]*:[a-z][a-z0-9-]*$')
);
CREATE INDEX group_invite_links_group_idx
  ON group_invite_links (permission_group_id);
CREATE INDEX group_invite_links_invited_by_idx
  ON group_invite_links (invited_by);
CREATE INDEX group_invite_links_terminal_idx
  ON group_invite_links (LEAST(redeemed_at, revoked_at, expires_at), id);
CREATE INDEX group_invite_links_tenant_idx ON group_invite_links(tenant_id,id);
COMMENT ON COLUMN group_invite_links.invited_by IS 'The issuing user; NULL = issued by the operator.';
COMMENT ON COLUMN group_invite_links.catalog_issuer IS 'The Token.Issuer of the app that issued the link; only its role catalog judges it. NULL = every app does.';
CREATE TRIGGER group_invite_links_tenant_immutable BEFORE UPDATE OF tenant_id ON group_invite_links FOR EACH ROW EXECUTE FUNCTION preserve_tenant_ownership();

CREATE TABLE account_registration_invites (
  id uuid PRIMARY KEY DEFAULT uuidv7(),
  email public.citext NOT NULL,
  invited_by uuid REFERENCES users(id) ON DELETE CASCADE,
  code_hash text NOT NULL UNIQUE,
  expires_at timestamptz NOT NULL,
  revoked_at timestamptz,
  consumed_at timestamptz,
  permission_group_id uuid REFERENCES permission_groups(id) ON DELETE CASCADE,
  role text,
  created_at timestamptz NOT NULL DEFAULT now(),
  catalog_issuer text,
  tenant_id uuid NOT NULL REFERENCES tenants(id),
  CONSTRAINT ari_role_format_chk CHECK (role IS NULL OR role ~ '^[a-z][a-z0-9-]*:[a-z][a-z0-9-]*$'),
  CONSTRAINT ari_group_role_pairing_chk CHECK (role IS NULL OR permission_group_id IS NOT NULL)
);
CREATE INDEX account_registration_invites_invited_by_idx
  ON account_registration_invites (invited_by);
CREATE INDEX account_registration_invites_terminal_idx
  ON account_registration_invites (LEAST(consumed_at, revoked_at, expires_at), id);
CREATE INDEX account_registration_invites_group_idx
  ON account_registration_invites (permission_group_id);
CREATE INDEX account_registration_invites_tenant_email_idx ON account_registration_invites(tenant_id,email);
COMMENT ON COLUMN account_registration_invites.invited_by IS 'The issuing user; NULL = issued by the operator.';
COMMENT ON COLUMN account_registration_invites.catalog_issuer IS 'The Token.Issuer of the app that issued the invite; only its role catalog judges it. NULL = every app does.';
CREATE TRIGGER account_registration_invites_tenant_immutable BEFORE UPDATE OF tenant_id ON account_registration_invites FOR EACH ROW EXECUTE FUNCTION preserve_tenant_ownership();

CREATE FUNCTION enforce_invitation_tenant() RETURNS trigger
LANGUAGE plpgsql SET search_path FROM CURRENT AS $$
DECLARE owner uuid; invite_tenant uuid; target_group uuid; target_persona text; invited_role text;
BEGIN
 IF TG_TABLE_NAME='account_registration_invites' THEN
  SELECT tenant_id,permission_group_id,role INTO invite_tenant,target_group,invited_role FROM account_registration_invites WHERE id=NEW.id;
 ELSE
  SELECT tenant_id,permission_group_id INTO invite_tenant,target_group FROM group_invite_links WHERE id=NEW.id;
 END IF;
 IF NOT FOUND THEN RETURN NULL; END IF;
 SELECT tenant_id,persona INTO owner,target_persona FROM permission_groups WHERE id=target_group;
 IF TG_TABLE_NAME='account_registration_invites' AND invited_role IS NULL AND target_group IS NOT NULL
    AND target_persona NOT IN ('root','tenant') THEN
  RAISE EXCEPTION 'a role-less invitation requires a root or tenant authority group' USING ERRCODE='23514';
 END IF;
 IF owner IS NOT NULL AND invite_tenant IS DISTINCT FROM owner THEN
  RAISE EXCEPTION 'invitation and group tenant must match' USING ERRCODE='23514';
 END IF;
 RETURN NULL;
END;
$$;
CREATE CONSTRAINT TRIGGER account_registration_invites_tenant_owner AFTER INSERT OR UPDATE ON account_registration_invites
DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION enforce_invitation_tenant();
CREATE CONSTRAINT TRIGGER group_invite_links_tenant_owner AFTER INSERT OR UPDATE ON group_invite_links
DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION enforce_invitation_tenant();

-- Each app's role catalog as its credential sweep last reconciled it. An app
-- without a row sweeps its credentials at its next boot.
CREATE TABLE role_catalogs (
  issuer text PRIMARY KEY,
  fingerprint text NOT NULL,
  roles text[] NOT NULL,
  swept_at timestamptz NOT NULL DEFAULT now()
);
COMMENT ON COLUMN role_catalogs.roles IS 'The persona:role names the catalog declares; no other app counts them as drift.';


-- Remote users: a group's directory of its remote applications' users (SCIM
-- 2.0, RFC 7643 and RFC 7644), each known by its issuer and subject, which
-- only together identify a user (OpenID Connect Core §2, §5.7). A SCIM client
-- provisions them (provisioned_at), or a token's contact claims record them.
CREATE TABLE remote_users (
  id uuid PRIMARY KEY DEFAULT uuidv7(),
  permission_group_id uuid NOT NULL REFERENCES permission_groups(id) ON DELETE CASCADE,
  issuer text NOT NULL CHECK (issuer <> ''),
  subject text NOT NULL CHECK (subject <> '' AND char_length(subject) <= 255),
  user_name public.citext CHECK (user_name <> '' AND char_length(user_name) <= 256),
  display_name text CHECK (display_name <> '' AND char_length(display_name) <= 256),
  name_formatted text CHECK (name_formatted <> '' AND char_length(name_formatted) <= 256),
  given_name text CHECK (given_name <> '' AND char_length(given_name) <= 256),
  family_name text CHECK (family_name <> '' AND char_length(family_name) <= 256),
  email public.citext CHECK (email <> '' AND char_length(email) <= 320),
  email_type text CHECK (email_type <> '' AND char_length(email_type) <= 256),
  active boolean NOT NULL DEFAULT true,
  provisioned_at timestamptz,
  source_updated_at timestamptz,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  CONSTRAINT remote_users_subject_key UNIQUE (permission_group_id, issuer, subject)
);
CREATE UNIQUE INDEX remote_users_user_name_key
  ON remote_users (permission_group_id, issuer, user_name)
  WHERE provisioned_at IS NOT NULL;
CREATE INDEX remote_users_provisioned_idx
  ON remote_users (permission_group_id, issuer, id)
  WHERE provisioned_at IS NOT NULL;
COMMENT ON TABLE remote_users IS
  'The users of the issuers a group trusts, by issuer and subject: SCIM-provisioned or recorded from token claims; a SCIM DELETE deletes the row.';
COMMENT ON COLUMN remote_users.subject IS 'The issuer''s sub for the user: the SCIM externalId';
COMMENT ON COLUMN remote_users.email IS 'An address the issuer asserts: pushed over SCIM, or an email claim with email_verified';
COMMENT ON COLUMN remote_users.provisioned_at IS 'When a SCIM client created the User (meta.created); NULL when only token claims recorded it';
COMMENT ON COLUMN remote_users.source_updated_at IS 'When the values were last reported: a SCIM write''s arrival, or a token''s updated_at claim. An older claim is ignored';

-- A role in a group held by a trusted issuer's user (its remote_users row),
-- granted by an email invitation the user accepted with that verified
-- address. Its tokens hold the role's permissions there, within their
-- application's role as ever. Deleting the user or the group deletes it.
CREATE TABLE group_remote_user_roles (
  permission_group_id uuid NOT NULL REFERENCES permission_groups(id) ON DELETE CASCADE,
  remote_user_id uuid NOT NULL REFERENCES remote_users(id) ON DELETE CASCADE,
  role text NOT NULL CONSTRAINT grur_role_format_chk CHECK (role ~ '^[a-z][a-z0-9-]*:[a-z][a-z0-9-]*$'),
  invitation_id uuid REFERENCES account_registration_invites(id) ON DELETE SET NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (permission_group_id, remote_user_id)
);
CREATE INDEX group_remote_user_roles_user_idx ON group_remote_user_roles (remote_user_id);
CREATE INDEX group_remote_user_roles_invitation_idx ON group_remote_user_roles (invitation_id) WHERE invitation_id IS NOT NULL;
COMMENT ON TABLE group_remote_user_roles IS
  'Roles trusted issuers'' users hold in groups, from accepted email invitations; kept while the user and group are.';


-- Group OAuth clients: OAuth clients a group registers at run time (RFC 7591
-- metadata), each user's consent to them, and the pairwise subjects (OIDC
-- Core §8.1) by which a group's clients know a user.
CREATE TABLE group_oauth_clients (
  client_id text PRIMARY KEY CONSTRAINT goc_client_id_chk CHECK (client_id ~ '^goc_[a-z2-7]{26}$'),
  permission_group_id uuid NOT NULL REFERENCES permission_groups(id) ON DELETE CASCADE,
  client_name text NOT NULL CONSTRAINT goc_name_chk CHECK (length(client_name) BETWEEN 1 AND 128),
  logo_uri text CONSTRAINT goc_logo_chk CHECK (logo_uri <> ''),
  client_uri text CONSTRAINT goc_client_uri_chk CHECK (client_uri <> ''),
  policy_uri text CONSTRAINT goc_policy_chk CHECK (policy_uri <> ''),
  tos_uri text CONSTRAINT goc_tos_chk CHECK (tos_uri <> ''),
  redirect_uris text[] NOT NULL CONSTRAINT goc_redirects_chk CHECK (cardinality(redirect_uris) BETWEEN 1 AND 10),
  post_logout_redirect_uris text[] NOT NULL DEFAULT '{}' CONSTRAINT goc_logout_redirects_chk CHECK (cardinality(post_logout_redirect_uris) <= 10),
  token_endpoint_auth_method text NOT NULL CONSTRAINT goc_auth_method_chk CHECK (token_endpoint_auth_method IN ('private_key_jwt', 'client_secret_basic', 'none')),
  secret_hash text,
  jwks_uri text,
  scopes text[] NOT NULL CONSTRAINT goc_scopes_chk CHECK ('openid' = ANY(scopes)),
  backchannel_logout_uri text CONSTRAINT goc_backchannel_chk CHECK (backchannel_logout_uri <> ''),
  disabled_at timestamptz,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  CONSTRAINT goc_secret_chk CHECK ((token_endpoint_auth_method = 'client_secret_basic') = (secret_hash IS NOT NULL)),
  CONSTRAINT goc_jwks_chk CHECK ((token_endpoint_auth_method = 'private_key_jwt') = (jwks_uri IS NOT NULL))
);
CREATE INDEX group_oauth_clients_group_idx ON group_oauth_clients (permission_group_id);
COMMENT ON TABLE group_oauth_clients IS
  'OAuth clients groups register at run time (RFC 7591 metadata): third-party clients whose users consent per scope, and whose tokens act only in their group. Deleted with the group.';

CREATE TABLE oauth_consents (
  user_id uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  client_id text NOT NULL REFERENCES group_oauth_clients(client_id) ON DELETE CASCADE,
  scopes text[] NOT NULL,
  granted_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (user_id, client_id)
);
CREATE INDEX oauth_consents_client_idx ON oauth_consents (client_id);
COMMENT ON TABLE oauth_consents IS
  'Each user''s consent to a group OAuth client: the scopes it may ask without asking again. Withdrawing it ends the client''s refresh tokens for the user.';

CREATE TABLE oauth_pairwise_subjects (
  permission_group_id uuid NOT NULL REFERENCES permission_groups(id) ON DELETE CASCADE,
  user_id uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  subject uuid NOT NULL DEFAULT gen_random_uuid() CONSTRAINT oauth_pairwise_subjects_subject_key UNIQUE,
  created_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (permission_group_id, user_id)
);
CREATE INDEX oauth_pairwise_subjects_user_idx ON oauth_pairwise_subjects (user_id);
COMMENT ON TABLE oauth_pairwise_subjects IS
  'Each user''s pairwise subject at each group whose OAuth clients get pairwise subjects: random, stable for the pair, mapped back only here. Deleted with the user or the group.';


-- Account lifecycle. Deletion is recoverable for thirty days; River owns
-- scheduling and execution. Applications may share identities while running
-- separate River schemas.
CREATE TABLE account_delivery_fleets (
  issuer text PRIMARY KEY,
  river_schema text NOT NULL
);
COMMENT ON TABLE account_delivery_fleets IS 'Configured account issuer destinations for required cleanup and credential operations; not event readers.';

-- Tenant ownership survives account removal, for all asynchronous deliveries.
CREATE TABLE account_deletions (
  id uuid PRIMARY KEY DEFAULT uuidv7(),
  user_id uuid NOT NULL,
  deleted_at timestamptz NOT NULL,
  purge_at timestamptz NOT NULL,
  state text NOT NULL DEFAULT 'deleted' CHECK (state IN ('deleted', 'restored', 'finalizing', 'purged')),
  recipients text[] NOT NULL DEFAULT '{}',
  restored_at timestamptz,
  purged_at timestamptz,
  deleted_by uuid,
  tenant_id uuid NOT NULL REFERENCES tenants(id),
  -- An operator purge ends the recovery window early.
  CONSTRAINT account_deletions_purge_window_chk
    CHECK (purge_at >= deleted_at AND purge_at <= deleted_at + interval '720 hours')
);
CREATE UNIQUE INDEX account_deletions_active_user_idx
  ON account_deletions (user_id)
  WHERE state IN ('deleted', 'finalizing');
CREATE INDEX account_deletions_user_idx
  ON account_deletions (user_id, deleted_at, id);
CREATE INDEX account_deletions_terminal_idx
  ON account_deletions ((COALESCE(restored_at, purged_at)), id)
  WHERE state IN ('restored', 'purged');
CREATE INDEX account_deletions_tenant_idx ON account_deletions(tenant_id,id);
-- The due sweep reads due lifecycle state; River stores no account deadlines.
CREATE INDEX account_deletions_due_idx ON account_deletions (purge_at, id)
  WHERE state IN ('deleted', 'finalizing');
COMMENT ON COLUMN account_deletions.deleted_by IS 'The user who deleted the account; NULL = the operator.';
CREATE TRIGGER account_deletions_tenant_immutable BEFORE UPDATE OF tenant_id ON account_deletions FOR EACH ROW EXECUTE FUNCTION preserve_tenant_ownership();

CREATE TABLE account_deletion_deliveries (
  id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  deletion_id uuid NOT NULL REFERENCES account_deletions(id) ON DELETE CASCADE,
  user_id uuid NOT NULL,
  issuer text NOT NULL,
  stage text NOT NULL CHECK (stage IN ('soft', 'restore', 'hard')),
  completed_at timestamptz,
  UNIQUE (deletion_id, issuer, stage)
);
CREATE INDEX account_deletion_deliveries_pending_idx
  ON account_deletion_deliveries (user_id, issuer, id)
  WHERE completed_at IS NULL;
CREATE INDEX account_deletion_deliveries_pending_deletion_idx ON account_deletion_deliveries (deletion_id)
  WHERE stage = 'hard' AND completed_at IS NULL;


-- SCIM 2.0 provisioning (Config.Provisioning). A change to what a SCIM User
-- shows (email and its verification, username, deletion, ban) records one
-- provisioning_changes row per target of its tenant in the change's own
-- transaction, whoever writes users: the triggers below are the only writers,
-- and each wakes its target's run (NOTIFY authkit_provisioning). A target's
-- batch sends each pending user's current state and deletes the rows the
-- target accepted. users.profile_updated_at is when those fields last
-- changed: SCIM meta.lastModified and the OIDC updated_at claim.
CREATE TABLE provisioning_targets (
  issuer text NOT NULL,
  name text NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  -- The initial sync queues every account in id order; sync_after is how far
  -- it got, synced_at when it finished.
  sync_after uuid,
  synced_at timestamptz,
  reconciled_at timestamptz,
  -- A reconciliation spans runs: when it began, the next startIndex of its
  -- listing of the target's users, and when that listing finished (the
  -- resources it did not see are then checked one by one).
  reconcile_started_at timestamptz,
  reconcile_next_index integer,
  reconcile_listed_at timestamptz,
  last_success_at timestamptz,
  failing_since timestamptz,
  failures integer NOT NULL DEFAULT 0,
  retry_at timestamptz,
  last_error text,
  tenant_id uuid NOT NULL REFERENCES tenants(id),
  PRIMARY KEY (issuer, name),
  CONSTRAINT provisioning_targets_tenant_key UNIQUE (issuer, name, tenant_id)
);
COMMENT ON TABLE provisioning_targets IS 'SCIM targets of each issuer''s Config.Provisioning; a target no longer configured is deleted at its issuer''s Start.';
CREATE TRIGGER provisioning_targets_tenant_immutable BEFORE UPDATE OF tenant_id ON provisioning_targets FOR EACH ROW EXECUTE FUNCTION preserve_tenant_ownership();

-- The outbox: a user with a row is pending for the target. Rows reference no
-- user: a purge must leave its own row behind.
CREATE TABLE provisioning_changes (
  id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  issuer text NOT NULL,
  target text NOT NULL,
  user_id uuid NOT NULL,
  due_at timestamptz NOT NULL DEFAULT now(),
  attempts integer NOT NULL DEFAULT 0,
  last_error text,
  tenant_id uuid NOT NULL,
  FOREIGN KEY (issuer, target) REFERENCES provisioning_targets ON DELETE CASCADE,
  CONSTRAINT provisioning_changes_tenant_fk FOREIGN KEY (issuer, target, tenant_id)
    REFERENCES provisioning_targets(issuer, name, tenant_id) ON DELETE CASCADE
);
CREATE INDEX provisioning_changes_due_idx
  ON provisioning_changes (issuer, target, due_at, id);
CREATE INDEX provisioning_changes_user_idx
  ON provisioning_changes (issuer, target, user_id, id);
COMMENT ON COLUMN provisioning_changes.due_at IS 'Not sent before: a retry''s backoff, or a temporary ban''s end';

-- What each target holds: the id it gave the user and the digest of the
-- state it last accepted.
CREATE TABLE provisioning_resources (
  issuer text NOT NULL,
  target text NOT NULL,
  user_id uuid NOT NULL,
  remote_id text NOT NULL,
  state_digest text NOT NULL,
  synced_at timestamptz NOT NULL DEFAULT now(),
  seen_at timestamptz,
  tenant_id uuid NOT NULL,
  PRIMARY KEY (issuer, target, user_id),
  FOREIGN KEY (issuer, target) REFERENCES provisioning_targets ON DELETE CASCADE,
  CONSTRAINT provisioning_resources_tenant_fk FOREIGN KEY (issuer, target, tenant_id)
    REFERENCES provisioning_targets(issuer, name, tenant_id) ON DELETE CASCADE
);
COMMENT ON COLUMN provisioning_resources.state_digest IS 'SHA-256 of the resource the target last accepted; empty when reconciliation found it drifted';
COMMENT ON COLUMN provisioning_resources.seen_at IS 'When reconciliation last found the resource at the target';

CREATE FUNCTION provisioning_touch_profile() RETURNS trigger
LANGUAGE plpgsql SET search_path FROM CURRENT AS $$
BEGIN
  NEW.profile_updated_at := statement_timestamp();
  RETURN NEW;
END;
$$;
CREATE TRIGGER users_profile_updated
  BEFORE UPDATE OF email, email_verified, username, deleted_at, banned_at, banned_until ON users
  FOR EACH ROW
  WHEN (ROW(OLD.email, OLD.email_verified, OLD.username, OLD.deleted_at, OLD.banned_at, OLD.banned_until)
        IS DISTINCT FROM ROW(NEW.email, NEW.email_verified, NEW.username, NEW.deleted_at, NEW.banned_at, NEW.banned_until))
  EXECUTE FUNCTION provisioning_touch_profile();

-- One channel for every schema: "<schema>.provisioning" can pass a channel
-- name's 63 bytes.
CREATE FUNCTION provisioning_record_change() RETURNS trigger
LANGUAGE plpgsql SET search_path FROM CURRENT AS $$
DECLARE owner uuid; subject_id uuid; recorded record;
BEGIN
 IF TG_OP='DELETE' THEN owner:=OLD.tenant_id; subject_id:=OLD.id;
 ELSE owner:=NEW.tenant_id; subject_id:=NEW.id; END IF;
 FOR recorded IN
  INSERT INTO provisioning_changes(issuer,target,user_id,tenant_id)
  SELECT issuer,name,subject_id,tenant_id FROM provisioning_targets WHERE tenant_id=owner
  RETURNING issuer,target
 LOOP
  PERFORM pg_notify('authkit_provisioning',
   json_build_object('schema',TG_TABLE_SCHEMA,'issuer',recorded.issuer,'target',recorded.target)::text);
 END LOOP;
 RETURN NULL;
END;
$$;
CREATE TRIGGER users_provisioning_insert
  AFTER INSERT ON users
  FOR EACH ROW EXECUTE FUNCTION provisioning_record_change();
CREATE TRIGGER users_provisioning_update
  AFTER UPDATE OF email, email_verified, username, deleted_at, banned_at, banned_until ON users
  FOR EACH ROW
  WHEN (ROW(OLD.email, OLD.email_verified, OLD.username, OLD.deleted_at, OLD.banned_at, OLD.banned_until)
        IS DISTINCT FROM ROW(NEW.email, NEW.email_verified, NEW.username, NEW.deleted_at, NEW.banned_at, NEW.banned_until))
  EXECUTE FUNCTION provisioning_record_change();
CREATE TRIGGER users_provisioning_delete
  AFTER DELETE ON users
  FOR EACH ROW EXECUTE FUNCTION provisioning_record_change();


-- Runtime state. ephemeral_kv holds short-lived, single-use auth state shared
-- by every replica: codes, tokens, ceremonies, OIDC/SIWS state and attempt
-- counters. Rows past expires_at are invisible to reads and purged by the
-- maintenance job.
CREATE TABLE ephemeral_kv (
  key text PRIMARY KEY,
  value bytea NOT NULL,
  expires_at timestamptz NOT NULL
);
CREATE INDEX ephemeral_kv_expires_at_idx
  ON ephemeral_kv (expires_at);

-- The bootstrap manifests that claimed this schema, by name.
CREATE TABLE bootstrap_applies (
  name text PRIMARY KEY,
  applied_at timestamptz NOT NULL DEFAULT now()
);


-- Events: one retained record per committed event, in Helpers' shared event
-- log (eventlog/postgres). Readers own their cursors; no subscription,
-- acknowledgement or delivery state belongs to this log. Every stream's epoch
-- is the deployment's (event_log_instance).
CREATE TABLE event_log_instance (
    singleton boolean PRIMARY KEY DEFAULT true CHECK (singleton),
    epoch uuid NOT NULL DEFAULT gen_random_uuid()
);
INSERT INTO event_log_instance DEFAULT VALUES;

DO $migration$
BEGIN
 EXECUTE replace($helpers$
-- BEGIN helpers/eventlog/postgres schema v1 (verbatim; checked by test)
CREATE TABLE IF NOT EXISTS "__authkit_eventlog_schema__".eventlog_migrations(version integer PRIMARY KEY);
CREATE TABLE "__authkit_eventlog_schema__".eventlog_streams (
 source text NOT NULL, scope text NOT NULL,
 epoch text NOT NULL DEFAULT gen_random_uuid()::text,
 position bigint NOT NULL DEFAULT 0,
 head_id text NOT NULL DEFAULT '',
 pruned_through bigint NOT NULL DEFAULT 0,
 pruned_id text NOT NULL DEFAULT '',
 recorded_at timestamptz NOT NULL DEFAULT '-infinity',
 PRIMARY KEY(source,scope)
);
CREATE TABLE "__authkit_eventlog_schema__".eventlog_events (
 source text NOT NULL, scope text NOT NULL, position bigint NOT NULL,
 id text NOT NULL, boundary text NOT NULL, event_source text NOT NULL, event_type text NOT NULL, version integer NOT NULL,
 occurred_at timestamptz NOT NULL, recorded_at timestamptz NOT NULL,
 subject_type text NOT NULL, subject_id text NOT NULL, data jsonb NOT NULL,
 PRIMARY KEY(source,scope,position), UNIQUE(source,scope,id),
 FOREIGN KEY(source,scope) REFERENCES "__authkit_eventlog_schema__".eventlog_streams(source,scope) ON DELETE CASCADE
);
CREATE INDEX ON "__authkit_eventlog_schema__".eventlog_events(source,scope,event_type,position);
CREATE INDEX ON "__authkit_eventlog_schema__".eventlog_events(source,scope,recorded_at,position);
-- A queue row is part of the mutation transaction and is gone before commit.
-- The identity orders facts inside that transaction, never public cursors.
CREATE TABLE "__authkit_eventlog_schema__".eventlog_pending (
 ordinal bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
 transaction_id xid8 NOT NULL DEFAULT pg_current_xact_id(),
 source text NOT NULL CHECK(source<>''), scope text NOT NULL CHECK(scope<>''),
 id text NOT NULL CHECK(id<>''), boundary text, event_source text NOT NULL, event_type text NOT NULL CHECK(event_type<>''),
 version integer NOT NULL CHECK(version>0), occurred_at timestamptz NOT NULL,
 subject_type text NOT NULL DEFAULT '', subject_id text NOT NULL DEFAULT '', data jsonb NOT NULL
);
CREATE INDEX ON "__authkit_eventlog_schema__".eventlog_pending(transaction_id);
CREATE FUNCTION "__authkit_eventlog_schema__".eventlog_flush() RETURNS trigger LANGUAGE plpgsql SET search_path TO pg_catalog,pg_temp AS $fn$
DECLARE
 s record; e record; next_position bigint; stamp timestamptz;
BEGIN
 -- Every scope touched by this transaction is known before taking any locks.
 FOR s IN SELECT DISTINCT source,scope FROM "__authkit_eventlog_schema__".eventlog_pending
          WHERE transaction_id=pg_current_xact_id() ORDER BY source,scope
 LOOP
  INSERT INTO "__authkit_eventlog_schema__".eventlog_streams(source,scope) VALUES(s.source,s.scope) ON CONFLICT DO NOTHING;
  PERFORM 1 FROM "__authkit_eventlog_schema__".eventlog_streams WHERE source=s.source AND scope=s.scope FOR UPDATE;
 END LOOP;
 FOR e IN SELECT * FROM "__authkit_eventlog_schema__".eventlog_pending WHERE transaction_id=pg_current_xact_id() ORDER BY ordinal
 LOOP
  IF EXISTS(SELECT 1 FROM "__authkit_eventlog_schema__".eventlog_events WHERE source=e.source AND scope=e.scope AND id=e.id) THEN
   IF EXISTS(SELECT 1 FROM "__authkit_eventlog_schema__".eventlog_events WHERE source=e.source AND scope=e.scope AND id=e.id
     AND event_source=e.event_source AND event_type=e.event_type AND version=e.version
     AND occurred_at=e.occurred_at AND subject_type=e.subject_type AND subject_id=e.subject_id AND data=e.data) THEN
    CONTINUE;
   END IF;
   RAISE EXCEPTION 'event ID already records a different fact' USING ERRCODE='23505';
  END IF;
  UPDATE "__authkit_eventlog_schema__".eventlog_streams SET position=position+1,head_id=coalesce(e.boundary,e.id),
   recorded_at=greatest(recorded_at,clock_timestamp())
   WHERE source=e.source AND scope=e.scope RETURNING position,recorded_at INTO next_position,stamp;
  INSERT INTO "__authkit_eventlog_schema__".eventlog_events(source,scope,position,id,boundary,event_source,event_type,version,occurred_at,recorded_at,subject_type,subject_id,data)
   VALUES(e.source,e.scope,next_position,e.id,coalesce(e.boundary,e.id),e.event_source,e.event_type,e.version,e.occurred_at,stamp,e.subject_type,e.subject_id,e.data);
 END LOOP;
 DELETE FROM "__authkit_eventlog_schema__".eventlog_pending WHERE transaction_id=pg_current_xact_id();
 RETURN NULL;
END $fn$;
CREATE CONSTRAINT TRIGGER eventlog_flush_at_commit AFTER INSERT ON "__authkit_eventlog_schema__".eventlog_pending
 DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION "__authkit_eventlog_schema__".eventlog_flush();

CREATE FUNCTION "__authkit_eventlog_schema__".eventlog_immutable() RETURNS trigger LANGUAGE plpgsql SET search_path TO pg_catalog,pg_temp AS $fn$
BEGIN
 RAISE EXCEPTION 'retained event facts are immutable';
END $fn$;
CREATE TRIGGER eventlog_immutable BEFORE UPDATE ON "__authkit_eventlog_schema__".eventlog_events
 FOR EACH ROW EXECUTE FUNCTION "__authkit_eventlog_schema__".eventlog_immutable();

INSERT INTO "__authkit_eventlog_schema__".eventlog_migrations(version) VALUES(1);
-- END helpers/eventlog/postgres schema v1
$helpers$, '"__authkit_eventlog_schema__"', quote_ident(current_schema()));
END
$migration$;
DO $migration$
BEGIN
 EXECUTE replace($helpers$
-- BEGIN helpers/eventlog/postgres schema v2 (verbatim)
-- Version 2: the flush notifies "<schema>.eventlog" with "<source> <scope>" for each stream it advances.
CREATE OR REPLACE FUNCTION "__authkit_eventlog_schema__".eventlog_flush() RETURNS trigger LANGUAGE plpgsql SET search_path TO pg_catalog,pg_temp AS $fn$
DECLARE
 s record; e record; next_position bigint; stamp timestamptz;
BEGIN
 -- Every scope touched by this transaction is known before taking any locks.
 FOR s IN SELECT DISTINCT source,scope FROM "__authkit_eventlog_schema__".eventlog_pending
          WHERE transaction_id=pg_current_xact_id() ORDER BY source,scope
 LOOP
  INSERT INTO "__authkit_eventlog_schema__".eventlog_streams(source,scope) VALUES(s.source,s.scope) ON CONFLICT DO NOTHING;
  PERFORM 1 FROM "__authkit_eventlog_schema__".eventlog_streams WHERE source=s.source AND scope=s.scope FOR UPDATE;
  -- Delivered at commit, so a LISTENing consumer reads when its stream has moved (version 2).
  PERFORM pg_notify(TG_TABLE_SCHEMA || '.eventlog', s.source || ' ' || s.scope);
 END LOOP;
 FOR e IN SELECT * FROM "__authkit_eventlog_schema__".eventlog_pending WHERE transaction_id=pg_current_xact_id() ORDER BY ordinal
 LOOP
  IF EXISTS(SELECT 1 FROM "__authkit_eventlog_schema__".eventlog_events WHERE source=e.source AND scope=e.scope AND id=e.id) THEN
   IF EXISTS(SELECT 1 FROM "__authkit_eventlog_schema__".eventlog_events WHERE source=e.source AND scope=e.scope AND id=e.id
     AND event_source=e.event_source AND event_type=e.event_type AND version=e.version
     AND occurred_at=e.occurred_at AND subject_type=e.subject_type AND subject_id=e.subject_id AND data=e.data) THEN
    CONTINUE;
   END IF;
   RAISE EXCEPTION 'event ID already records a different fact' USING ERRCODE='23505';
  END IF;
  UPDATE "__authkit_eventlog_schema__".eventlog_streams SET position=position+1,head_id=coalesce(e.boundary,e.id),
   recorded_at=greatest(recorded_at,clock_timestamp())
   WHERE source=e.source AND scope=e.scope RETURNING position,recorded_at INTO next_position,stamp;
  INSERT INTO "__authkit_eventlog_schema__".eventlog_events(source,scope,position,id,boundary,event_source,event_type,version,occurred_at,recorded_at,subject_type,subject_id,data)
   VALUES(e.source,e.scope,next_position,e.id,coalesce(e.boundary,e.id),e.event_source,e.event_type,e.version,e.occurred_at,stamp,e.subject_type,e.subject_id,e.data);
 END LOOP;
 DELETE FROM "__authkit_eventlog_schema__".eventlog_pending WHERE transaction_id=pg_current_xact_id();
 RETURN NULL;
END $fn$;

INSERT INTO "__authkit_eventlog_schema__".eventlog_migrations(version) VALUES(2);
-- END helpers/eventlog/postgres schema v2
$helpers$, '"__authkit_eventlog_schema__"', quote_ident(current_schema()));
END
$migration$;

-- Every stream takes the deployment's epoch; no stream is created by a read.
DO $epoch$
BEGIN
 EXECUTE format('CREATE FUNCTION %I.event_log_default_epoch() RETURNS text LANGUAGE sql STABLE SET search_path=pg_catalog,pg_temp AS %L',
  current_schema(),format('SELECT epoch::text FROM %I.event_log_instance WHERE singleton',current_schema()));
END
$epoch$;
ALTER TABLE eventlog_streams ALTER COLUMN epoch SET DEFAULT event_log_default_epoch();
CREATE UNIQUE INDEX eventlog_authkit_event_identity ON eventlog_events((id::uuid)) WHERE source='authkit';
CREATE INDEX eventlog_authkit_retention ON eventlog_events(recorded_at,scope,position) WHERE source='authkit';

-- AuthKit's reads of its own streams.
CREATE VIEW event_log AS SELECT scope,position,id::uuid AS event_id,event_type AS kind,
 recorded_at,data AS payload FROM eventlog_events WHERE source='authkit';
CREATE VIEW event_log_scopes AS SELECT scope,position,pruned_through AS retained_after
 FROM eventlog_streams WHERE source='authkit';
