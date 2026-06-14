-- #79: Rename tenant -> ORG across AuthKit (hard cut). The AuthKit "tenant" is an
-- organization (members, roles, owner, à la GitHub orgs); "tenant" collided with
-- the OpenRails infra-isolation term (now `merchant`). One meaning per word.
--
--   * profiles.tenants table                -> orgs
--   * profiles.tenant_roles                 -> org_roles
--   * profiles.tenant_role_permissions      -> org_role_permissions
--   * profiles.tenant_memberships           -> org_memberships (polymorphic shape kept)
--   * profiles.tenant_invites               -> org_invites
--   * profiles.tenant_renames               -> org_renames
--   * tenant_id column                       -> org_id (every referencing table,
--     incl. remote_applications.tenant_id from #77)
--   * constraints/indexes/trigger carrying  -> org ("tenant" -> "org")
--   * owner_reserved_names is NOT org-scoped (global slug reservation) -> untouched.
--
-- The 001 baseline is FORCED to keep the tenant names: migrations 002/003/004/007
-- reference profiles.tenants / tenant_memberships / tenant_issuers / tenant_subjects
-- by name with UNGUARDED DDL, so a fresh DB must still create them as tenant_* before
-- this migration renames them (the money_settings forced-remnant case). sqlc parses
-- 001..009 cumulatively, so generated code sees the final org_* names regardless.
--
-- Idempotent + transactional: every rename is guarded, so it is a no-op on a fresh
-- DB whose later state already carries the org_* names.

SET lock_timeout = '10s';
SET statement_timeout = '300s';

-- ---------------------------------------------------------------------------
-- 1. Table renames. Top-level ALTER ... IF EXISTS so the sqlc parser sees the
--    final org_* names; the IF EXISTS makes a re-run a no-op.
-- ---------------------------------------------------------------------------
ALTER TABLE IF EXISTS profiles.tenants                  RENAME TO orgs;
ALTER TABLE IF EXISTS profiles.tenant_roles             RENAME TO org_roles;
ALTER TABLE IF EXISTS profiles.tenant_role_permissions  RENAME TO org_role_permissions;
ALTER TABLE IF EXISTS profiles.tenant_memberships       RENAME TO org_memberships;
ALTER TABLE IF EXISTS profiles.tenant_invites           RENAME TO org_invites;
ALTER TABLE IF EXISTS profiles.tenant_renames           RENAME TO org_renames;

-- ---------------------------------------------------------------------------
-- 2. Column rename: tenant_id -> org_id. TOP-LEVEL ALTER ... RENAME COLUMN (not a
--    dynamic DO block) so the sqlc parser sees the final org_id name; ALTER TABLE
--    IF EXISTS guards the table. Covers every table that carried tenant_id:
--    service_tokens, remote_applications (#77), and the org_* tables renamed above.
-- ---------------------------------------------------------------------------
ALTER TABLE IF EXISTS profiles.service_tokens        RENAME COLUMN tenant_id TO org_id;
ALTER TABLE IF EXISTS profiles.remote_applications   RENAME COLUMN tenant_id TO org_id;
ALTER TABLE IF EXISTS profiles.org_roles             RENAME COLUMN tenant_id TO org_id;
ALTER TABLE IF EXISTS profiles.org_role_permissions  RENAME COLUMN tenant_id TO org_id;
ALTER TABLE IF EXISTS profiles.org_memberships       RENAME COLUMN tenant_id TO org_id;
ALTER TABLE IF EXISTS profiles.org_invites           RENAME COLUMN tenant_id TO org_id;
ALTER TABLE IF EXISTS profiles.org_renames           RENAME COLUMN tenant_id TO org_id;

-- ---------------------------------------------------------------------------
-- 3. Rename constraints + indexes whose names carry "tenant" -> "org"
--    (e.g. tenants_pkey -> orgs_pkey, tenant_invites_status_chk ->
--    org_invites_status_chk, *_tenant_id_fkey -> *_org_id_fkey).
-- ---------------------------------------------------------------------------
DO $$
DECLARE
    r record;
BEGIN
    -- constraints (PK/FK/CHECK/UNIQUE/NOT NULL)
    FOR r IN
        SELECT con.conname, rel.relname AS table_name
          FROM pg_constraint con
          JOIN pg_class rel ON rel.oid = con.conrelid
          JOIN pg_namespace nsp ON nsp.oid = rel.relnamespace
         WHERE nsp.nspname = 'profiles' AND con.conname LIKE '%tenant%'
    LOOP
        EXECUTE format('ALTER TABLE profiles.%I RENAME CONSTRAINT %I TO %I',
                       r.table_name, r.conname,
                       replace(r.conname, 'tenant', 'org'));
    END LOOP;

    -- indexes not backing a constraint (partial/expression/plain)
    FOR r IN
        SELECT c.relname AS idxname
          FROM pg_class c
          JOIN pg_namespace nsp ON nsp.oid = c.relnamespace
         WHERE nsp.nspname = 'profiles' AND c.relkind = 'i'
           AND c.relname LIKE '%tenant%'
           AND NOT EXISTS (SELECT 1 FROM pg_constraint con WHERE con.conindid = c.oid)
    LOOP
        EXECUTE format('ALTER INDEX profiles.%I RENAME TO %I',
                       r.idxname, replace(r.idxname, 'tenant', 'org'));
    END LOOP;
END $$;

-- ---------------------------------------------------------------------------
-- 4. The polymorphic-membership FK trigger + its function carry "tenant" in
--    their names and message text. Recreate under the org name, drop the old.
-- ---------------------------------------------------------------------------
DO $$
BEGIN
    IF to_regclass('profiles.org_memberships') IS NOT NULL THEN
        CREATE OR REPLACE FUNCTION profiles.trg_org_membership_member_fk() RETURNS trigger
         LANGUAGE plpgsql
         AS $fn$
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
        $fn$;

        DROP TRIGGER IF EXISTS tenant_membership_member_fk ON profiles.org_memberships;
        DROP TRIGGER IF EXISTS org_membership_member_fk ON profiles.org_memberships;
        CREATE TRIGGER org_membership_member_fk
          BEFORE INSERT OR UPDATE OF member_id, member_kind ON profiles.org_memberships
          FOR EACH ROW EXECUTE FUNCTION profiles.trg_org_membership_member_fk();

        DROP FUNCTION IF EXISTS profiles.trg_tenant_membership_member_fk();
    END IF;
END $$;

-- ---------------------------------------------------------------------------
-- 5. Refresh column/table COMMENTs that still read "tenant" (they surface in
--    generated code). Top-level so the sqlc parser applies them over the
--    earlier baseline comments; idempotent (a comment is just overwritten).
-- ---------------------------------------------------------------------------
COMMENT ON COLUMN profiles.orgs.metadata IS
  'Arbitrary org metadata (internal/admin flags such as reserved)';
COMMENT ON TABLE profiles.remote_applications IS
  'Federation principals: external systems that authenticate by signing JWTs verified against their JWKS/public keys. Members of orgs with roles via polymorphic org_memberships.';
COMMENT ON COLUMN profiles.remote_applications.owner_user_id IS
  'Creator-audit only (nullable, SET NULL on user delete). Ownership lives in org_id.';
