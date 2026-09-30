-- parent: 3 sha256:e5a1aac276d59f0d50ca1f9ffbbcde8df819693a7b17b121b05fb69d9c0d4ca7
-- State earlier hard cuts left behind: the `reserved` flag, session families,
-- the 2FA `enabled` flag, passkey tombstones, name-claim kinds, and columns and
-- indexes nothing reads.
SET LOCAL lock_timeout = '10s';
SELECT set_config('search_path', format('%I, public, pg_temp', current_schema()), true);

-- `reserved` refused every sign-in, like a permanent ban, and becomes one. An
-- account whose ban is in force keeps its ban, made permanent.
CREATE OR REPLACE FUNCTION invalidate_recovery_grants() RETURNS trigger
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
UPDATE users SET
  banned_at = CASE WHEN ban_in_force(banned_at, banned_until) THEN banned_at ELSE statement_timestamp() END,
  ban_reason = CASE WHEN ban_in_force(banned_at, banned_until) THEN ban_reason ELSE 'reserved' END,
  banned_by = CASE WHEN ban_in_force(banned_at, banned_until) THEN banned_by END,
  banned_until = NULL
WHERE metadata->'reserved' = 'true'::jsonb;
UPDATE users SET metadata = metadata - 'reserved' WHERE metadata ? 'reserved';
COMMENT ON COLUMN users.metadata IS 'Host metadata';
CREATE OR REPLACE VIEW usable_users AS
SELECT id FROM users
WHERE deleted_at IS NULL AND NOT ban_in_force(banned_at, banned_until);

-- A session's family was always the session itself.
ALTER TABLE refresh_sessions DROP COLUMN family_id;

-- 2FA is on while the account has a factor. The backup codes go with the last
-- factor, so codes left by a disable are dropped here.
DELETE FROM mfa_settings s WHERE NOT EXISTS (SELECT 1 FROM mfa_factors f WHERE f.user_id = s.user_id);
INSERT INTO mfa_settings (user_id)
SELECT DISTINCT f.user_id FROM mfa_factors f
WHERE NOT EXISTS (SELECT 1 FROM mfa_settings s WHERE s.user_id = f.user_id);
ALTER TABLE mfa_settings DROP COLUMN enabled;
COMMENT ON TABLE mfa_settings IS 'Backup codes of an account with a second factor; the row goes with its last factor.';

-- A deleted passkey is deleted.
DELETE FROM user_passkeys WHERE deleted_at IS NOT NULL;
ALTER TABLE user_passkeys DROP COLUMN deleted_at;
CREATE UNIQUE INDEX uniq_user_passkeys_rpid_credential
  ON user_passkeys (rpid, credential_id);

-- Every name claim is a username.
ALTER TABLE name_claims DROP CONSTRAINT name_claims_user_chk;
ALTER TABLE name_claims DROP CONSTRAINT name_claims_pkey;
DROP INDEX name_claims_canonical_owner;
DROP INDEX name_claims_owner;
ALTER TABLE name_claims DROP COLUMN owner_kind, DROP COLUMN persona;
ALTER TABLE name_claims ADD PRIMARY KEY (name);
CREATE UNIQUE INDEX name_claims_canonical_owner ON name_claims (owner_id) WHERE canonical;
CREATE INDEX name_claims_owner ON name_claims (owner_id);

DROP FUNCTION claim_canonical_name(text, text, text, uuid, timestamptz);
DROP FUNCTION lock_name_claims(text, text, text[]);
-- The stripe input is the one v1.0 hashed, so every release locks alike.
CREATE FUNCTION lock_name_claims(handles text[]) RETURNS void
LANGUAGE plpgsql SET search_path FROM CURRENT AS $$
DECLARE stripe integer;
BEGIN
 FOR stripe IN SELECT DISTINCT (hashtextextended('user::' || lower(handle),631335) & 255)::integer
  FROM unnest(handles) AS handle WHERE COALESCE(handle,'')<>'' ORDER BY 1
 LOOP
  PERFORM pg_advisory_xact_lock(631335,stripe);
 END LOOP;
END;
$$;

CREATE FUNCTION claim_canonical_name(handle text, owner uuid, at_time timestamptz) RETURNS void
LANGUAGE plpgsql SET search_path FROM CURRENT AS $$
BEGIN
 IF COALESCE(handle, '') = '' THEN RETURN; END IF;
 PERFORM lock_name_claims(ARRAY[handle]);
 INSERT INTO name_claims(name, owner_id, canonical)
 VALUES (lower(handle), owner, true)
 ON CONFLICT (name) DO UPDATE
 SET owner_id = EXCLUDED.owner_id, canonical = true, expires_at = NULL
 WHERE name_claims.owner_id = owner
    OR (NOT name_claims.canonical AND name_claims.expires_at <= at_time);
 IF NOT FOUND THEN
  RAISE EXCEPTION 'name is unavailable' USING ERRCODE = '23505', CONSTRAINT = 'name_claims_pkey';
 END IF;
END;
$$;

CREATE OR REPLACE FUNCTION enforce_canonical_name_claim() RETURNS trigger
LANGUAGE plpgsql SET search_path FROM CURRENT AS $$
DECLARE handle text; previous text;
BEGIN
 IF TG_OP='UPDATE' AND NEW.id <> OLD.id THEN RAISE EXCEPTION 'identity UUID is immutable' USING ERRCODE='23514'; END IF;
 IF TG_OP = 'DELETE' THEN
  -- A deleted user's username stays reserved forever as an alias of the dead
  -- UUID, so nobody can re-register it and impersonate the purged account.
  UPDATE name_claims SET canonical=false, expires_at=NULL WHERE owner_id=OLD.id AND canonical;
  RETURN OLD;
 END IF;
 handle := NEW.username::text;
 IF TG_OP = 'INSERT' THEN
  PERFORM claim_canonical_name(handle, NEW.id, clock_timestamp());
 ELSE
  previous := OLD.username::text;
  IF lower(COALESCE(handle,'')) <> lower(COALESCE(previous,'')) AND (COALESCE(handle,'') = '' OR NOT EXISTS (
   SELECT 1 FROM name_claims WHERE name = lower(handle) AND owner_id = NEW.id AND canonical
  )) THEN RAISE EXCEPTION 'rename requires an atomic name claim' USING ERRCODE = '23514'; END IF;
 END IF;
 RETURN NEW;
END;
$$;
DROP TRIGGER users_name_claim ON users;
CREATE TRIGGER users_name_claim
  AFTER INSERT OR UPDATE OF id, username OR DELETE ON users
  FOR EACH ROW EXECUTE FUNCTION enforce_canonical_name_claim();

-- Written, never read.
ALTER TABLE group_invite_links DROP COLUMN updated_at;
ALTER TABLE account_registration_invites DROP COLUMN updated_at;
UPDATE user_providers SET profile = profile - 'verification_required' WHERE profile ? 'verification_required';
-- Serve no query.
DROP INDEX user_providers_slug_subject_idx;
DROP INDEX account_registration_invites_email_idx;
