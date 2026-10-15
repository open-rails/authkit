-- Canonical business ownership for AuthKit's shared account directory.
-- The runner supplies authkit.legacy_tenant_id only when explicitly configured.
SET LOCAL lock_timeout = '10s';

CREATE TABLE tenants (
  id uuid PRIMARY KEY,
  created_at timestamptz NOT NULL DEFAULT now(),
  CONSTRAINT tenants_nonzero CHECK (id <> '00000000-0000-0000-0000-000000000000'::uuid)
);
COMMENT ON TABLE tenants IS 'Canonical business identities shared with ContentKit; accounts of different tenants are independent.';

ALTER TABLE users ADD COLUMN tenant_id uuid REFERENCES tenants(id);
ALTER TABLE permission_groups ADD COLUMN tenant_id uuid REFERENCES tenants(id);

DO $$
DECLARE legacy uuid := NULLIF(current_setting('authkit.legacy_tenant_id', true), '')::uuid;
BEGIN
  IF legacy IS NULL AND (EXISTS(SELECT 1 FROM users) OR EXISTS(SELECT 1 FROM name_claims)
      OR EXISTS(SELECT 1 FROM permission_groups WHERE persona <> 'root') OR EXISTS(SELECT 1 FROM provisioning_targets) OR EXISTS(SELECT 1 FROM account_deletions)
      OR EXISTS(SELECT 1 FROM account_events WHERE user_id IS NOT NULL OR (persona <> 'root' AND (group_id IS NOT NULL OR application_id IS NOT NULL)))
      OR EXISTS(SELECT 1 FROM account_registration_invites) OR EXISTS(SELECT 1 FROM group_invite_links)) THEN
    RAISE EXCEPTION 'AuthKit tenant migration requires an explicit LegacyTenantID for the existing directory'
      USING ERRCODE = '55000';
  END IF;
  IF legacy IS NOT NULL THEN
    INSERT INTO tenants(id) VALUES(legacy);
    UPDATE users SET tenant_id=legacy;
    UPDATE permission_groups SET tenant_id=legacy WHERE persona <> 'root';
    INSERT INTO permission_groups(id,persona,tenant_id) VALUES(legacy,'tenant',legacy) ON CONFLICT(id) DO NOTHING;
    -- Preserve pending legacy proofs only in the explicitly adopted tenant.
    -- Deployment-wide abuse and replay guards intentionally remain global.
    UPDATE ephemeral_kv SET key='tenant:' || legacy::text || ':' || key
    WHERE key LIKE ANY(ARRAY[
      'email_verify:%','phone_verify:%','password_reset:%','password_proof:%',
      'passwordless:%','2fa:%','passkey:%','pending_change:%','oidc:%','siws:%',
      'device-key:%','step-up:%','account-recovery:%','signin:account:%',
      'signin:device-code:%','signin:device-sent:%','oauth:authz:%','oauth:code:%','oauth:refresh:%'
    ]);
  END IF;
END;
$$;

ALTER TABLE users ALTER COLUMN tenant_id SET NOT NULL;
ALTER TABLE users ADD CONSTRAINT users_tenant_id_id_key UNIQUE(tenant_id,id);
CREATE INDEX users_tenant_created_idx ON users(tenant_id,created_at,id);

ALTER TABLE permission_groups ADD CONSTRAINT permission_groups_tenant_scope_check
  CHECK ((persona = 'root' AND tenant_id IS NULL) OR (persona <> 'root' AND tenant_id IS NOT NULL));
ALTER TABLE permission_groups ADD CONSTRAINT permission_groups_tenant_identity_check
  CHECK (persona <> 'tenant' OR id=tenant_id);
CREATE INDEX permission_groups_tenant_idx ON permission_groups(tenant_id,id);

-- The account identifier namespace belongs to one business, not the shared DB.
ALTER TABLE users DROP CONSTRAINT users_username_key;
ALTER TABLE users DROP CONSTRAINT users_phone_number_key;
DROP INDEX users_email_uidx;
CREATE UNIQUE INDEX users_tenant_username_uidx ON users(tenant_id,username) WHERE username IS NOT NULL;
CREATE UNIQUE INDEX users_tenant_email_uidx ON users(tenant_id,email) WHERE email IS NOT NULL;
CREATE UNIQUE INDEX users_tenant_phone_uidx ON users(tenant_id,phone_number) WHERE phone_number IS NOT NULL;

ALTER TABLE name_claims ADD COLUMN tenant_id uuid REFERENCES tenants(id);
UPDATE name_claims SET tenant_id = NULLIF(current_setting('authkit.legacy_tenant_id', true),'')::uuid;
ALTER TABLE name_claims ALTER COLUMN tenant_id SET NOT NULL;
ALTER TABLE name_claims DROP CONSTRAINT name_claims_pkey;
ALTER TABLE name_claims ADD PRIMARY KEY(tenant_id,name);

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

DROP TRIGGER users_name_claim ON users;
DROP FUNCTION enforce_canonical_name_claim();
DROP FUNCTION claim_canonical_name(text, uuid, timestamptz);
DROP FUNCTION lock_name_claims(text[]);

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

ALTER TABLE user_providers ADD COLUMN tenant_id uuid;
UPDATE user_providers p SET tenant_id=u.tenant_id FROM users u WHERE u.id=p.user_id;
ALTER TABLE user_providers ALTER COLUMN tenant_id SET NOT NULL;
ALTER TABLE user_providers ADD CONSTRAINT user_providers_tenant_user_fk
 FOREIGN KEY(tenant_id,user_id) REFERENCES users(tenant_id,id) ON DELETE CASCADE;
ALTER TABLE user_providers DROP CONSTRAINT user_providers_issuer_subject_key;
CREATE UNIQUE INDEX user_providers_tenant_issuer_subject_key ON user_providers(tenant_id,issuer,subject);

-- SCIM targets and retained delivery receipts belong to one canonical tenant.
-- Receipts deliberately have no account FK: a purge must remain deliverable.
ALTER TABLE provisioning_targets ADD COLUMN tenant_id uuid REFERENCES tenants(id);
UPDATE provisioning_targets SET tenant_id=NULLIF(current_setting('authkit.legacy_tenant_id',true),'')::uuid;
ALTER TABLE provisioning_targets ALTER COLUMN tenant_id SET NOT NULL;
ALTER TABLE provisioning_targets ADD CONSTRAINT provisioning_targets_tenant_key UNIQUE(issuer,name,tenant_id);
ALTER TABLE provisioning_changes ADD COLUMN tenant_id uuid;
UPDATE provisioning_changes c SET tenant_id=t.tenant_id FROM provisioning_targets t WHERE t.issuer=c.issuer AND t.name=c.target;
ALTER TABLE provisioning_changes ALTER COLUMN tenant_id SET NOT NULL;
ALTER TABLE provisioning_changes ADD CONSTRAINT provisioning_changes_tenant_fk FOREIGN KEY(issuer,target,tenant_id) REFERENCES provisioning_targets(issuer,name,tenant_id) ON DELETE CASCADE;
ALTER TABLE provisioning_resources ADD COLUMN tenant_id uuid;
UPDATE provisioning_resources r SET tenant_id=t.tenant_id FROM provisioning_targets t WHERE t.issuer=r.issuer AND t.name=r.target;
ALTER TABLE provisioning_resources ALTER COLUMN tenant_id SET NOT NULL;
ALTER TABLE provisioning_resources ADD CONSTRAINT provisioning_resources_tenant_fk FOREIGN KEY(issuer,target,tenant_id) REFERENCES provisioning_targets(issuer,name,tenant_id) ON DELETE CASCADE;

CREATE FUNCTION preserve_tenant_ownership() RETURNS trigger
LANGUAGE plpgsql SET search_path FROM CURRENT AS $$
BEGIN
 IF NEW.tenant_id IS DISTINCT FROM OLD.tenant_id THEN
  RAISE EXCEPTION 'tenant ownership is immutable' USING ERRCODE='23514';
 END IF;
 RETURN NEW;
END;
$$;
CREATE TRIGGER permission_groups_tenant_immutable BEFORE UPDATE OF tenant_id ON permission_groups FOR EACH ROW EXECUTE FUNCTION preserve_tenant_ownership();
CREATE TRIGGER name_claims_tenant_immutable BEFORE UPDATE OF tenant_id ON name_claims FOR EACH ROW EXECUTE FUNCTION preserve_tenant_ownership();
CREATE TRIGGER provisioning_targets_tenant_immutable BEFORE UPDATE OF tenant_id ON provisioning_targets FOR EACH ROW EXECUTE FUNCTION preserve_tenant_ownership();

CREATE OR REPLACE FUNCTION provisioning_record_change() RETURNS trigger
LANGUAGE plpgsql SET search_path FROM CURRENT AS $$
DECLARE owner uuid; subject_id uuid;
BEGIN
 IF TG_OP='DELETE' THEN owner:=OLD.tenant_id; subject_id:=OLD.id;
 ELSE owner:=NEW.tenant_id; subject_id:=NEW.id; END IF;
 INSERT INTO provisioning_changes(issuer,target,user_id,tenant_id)
 SELECT issuer,name,subject_id,tenant_id FROM provisioning_targets WHERE tenant_id=owner;
 RETURN NULL;
END;
$$;


-- Tenant ownership survives account removal, for all asynchronous deliveries.
ALTER TABLE account_deletions ADD COLUMN tenant_id uuid REFERENCES tenants(id);
UPDATE account_deletions d SET tenant_id=COALESCE(
 (SELECT u.tenant_id FROM users u WHERE u.id=d.user_id),
 NULLIF(current_setting('authkit.legacy_tenant_id',true),'')::uuid);
ALTER TABLE account_deletions ALTER COLUMN tenant_id SET NOT NULL;
CREATE INDEX account_deletions_tenant_idx ON account_deletions(tenant_id,id);
CREATE TRIGGER account_deletions_tenant_immutable BEFORE UPDATE OF tenant_id ON account_deletions FOR EACH ROW EXECUTE FUNCTION preserve_tenant_ownership();

ALTER TABLE account_events ADD COLUMN tenant_id uuid REFERENCES tenants(id);
UPDATE account_events e SET tenant_id=CASE
 WHEN e.user_id IS NOT NULL THEN COALESCE(
  (SELECT u.tenant_id FROM users u WHERE u.id=e.user_id),
  NULLIF(current_setting('authkit.legacy_tenant_id',true),'')::uuid)
 WHEN EXISTS(SELECT 1 FROM permission_groups g WHERE g.id=e.group_id) THEN
  (SELECT g.tenant_id FROM permission_groups g WHERE g.id=e.group_id)
 WHEN EXISTS(SELECT 1 FROM remote_applications a WHERE a.id=e.application_id) THEN
  (SELECT g.tenant_id FROM remote_applications a JOIN permission_groups g ON g.id=a.permission_group_id WHERE a.id=e.application_id)
 WHEN e.persona='root' THEN NULL
 WHEN e.group_id IS NOT NULL OR e.application_id IS NOT NULL THEN
  NULLIF(current_setting('authkit.legacy_tenant_id',true),'')::uuid
 ELSE NULL END;
CREATE INDEX account_events_tenant_idx ON account_events(tenant_id,id);
CREATE TRIGGER account_events_tenant_immutable BEFORE UPDATE OF tenant_id ON account_events FOR EACH ROW EXECUTE FUNCTION preserve_tenant_ownership();


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

-- Even a root-group invitation targets one account directory. Its operator
-- may come from another tenant, so the inviter is not an ownership fallback.
ALTER TABLE account_registration_invites ADD COLUMN tenant_id uuid REFERENCES tenants(id);
UPDATE account_registration_invites i SET tenant_id=COALESCE(
 (SELECT g.tenant_id FROM permission_groups g WHERE g.id=i.permission_group_id),
 NULLIF(current_setting('authkit.legacy_tenant_id',true),'')::uuid);
ALTER TABLE account_registration_invites ALTER COLUMN tenant_id SET NOT NULL;
ALTER TABLE account_registration_invites DROP CONSTRAINT ari_group_role_pairing_chk;
ALTER TABLE account_registration_invites ADD CONSTRAINT ari_group_role_pairing_chk
 CHECK (role IS NULL OR permission_group_id IS NOT NULL);
CREATE INDEX account_registration_invites_tenant_email_idx ON account_registration_invites(tenant_id,email);
CREATE TRIGGER account_registration_invites_tenant_immutable BEFORE UPDATE OF tenant_id ON account_registration_invites FOR EACH ROW EXECUTE FUNCTION preserve_tenant_ownership();

ALTER TABLE group_invite_links ADD COLUMN tenant_id uuid REFERENCES tenants(id);
UPDATE group_invite_links i SET tenant_id=COALESCE(
 (SELECT g.tenant_id FROM permission_groups g WHERE g.id=i.permission_group_id),
 NULLIF(current_setting('authkit.legacy_tenant_id',true),'')::uuid);
ALTER TABLE group_invite_links ALTER COLUMN tenant_id SET NOT NULL;
CREATE INDEX group_invite_links_tenant_idx ON group_invite_links(tenant_id,id);
CREATE TRIGGER group_invite_links_tenant_immutable BEFORE UPDATE OF tenant_id ON group_invite_links FOR EACH ROW EXECUTE FUNCTION preserve_tenant_ownership();

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
