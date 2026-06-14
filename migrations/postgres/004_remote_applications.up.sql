-- #74: Split the dual-purpose tenant row into ORG (native `tenants`) and
-- REMOTE_APPLICATION (federation principal). A remote_application is a PRINCIPAL
-- like a user, but it authenticates by signing JWTs verified against its JWKS /
-- public keys instead of a password. It holds tenant memberships with roles via
-- the SAME machinery as users (polymorphic tenant_memberships).
--
-- This is a NEW numbered migration (NOT appended to 001): migratekit is
-- name-tracked, so tables added to an already-recorded 001 never reach existing
-- DBs (the service_tokens gotcha). Idempotent + transactional.

SET lock_timeout = '10s';
SET statement_timeout = '300s';

-- A remote_application: the federation principal. credential = JWKS XOR static
-- public keys (the same two trust modes the old tenant_issuers carried).
CREATE TABLE IF NOT EXISTS profiles.remote_applications (
  id            uuid PRIMARY KEY DEFAULT uuidv7(),
  slug          text NOT NULL UNIQUE,
  owner_user_id uuid REFERENCES profiles.users(id) ON DELETE RESTRICT,
  issuer        text NOT NULL UNIQUE,
  jwks_uri      text NOT NULL DEFAULT '',
  mode          text NOT NULL DEFAULT 'jwks',
  public_keys   jsonb,
  audiences     text[] NOT NULL DEFAULT '{}',
  enabled       boolean NOT NULL DEFAULT true,
  metadata      jsonb NOT NULL DEFAULT '{}'::jsonb,
  created_at    timestamptz NOT NULL DEFAULT now(),
  updated_at    timestamptz NOT NULL DEFAULT now(),
  deleted_at    timestamptz,
  CONSTRAINT remote_applications_slug_format_chk CHECK (
    char_length(slug) BETWEEN 1 AND 63
    AND slug ~ '^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$'
  ),
  CONSTRAINT remote_applications_mode_chk CHECK (mode IN ('jwks', 'static')),
  -- Exactly one trust source, never both (mirrors the old tenant_issuers XOR).
  CONSTRAINT remote_applications_trust_source_xor CHECK (
    (mode = 'jwks'   AND jwks_uri <> '' AND public_keys IS NULL)
    OR
    (mode = 'static' AND jwks_uri = '' AND public_keys IS NOT NULL
       AND jsonb_typeof(public_keys) = 'array' AND jsonb_array_length(public_keys) > 0)
  )
);
CREATE INDEX IF NOT EXISTS remote_applications_enabled_idx
  ON profiles.remote_applications (enabled)
  WHERE enabled = true;
CREATE INDEX IF NOT EXISTS remote_applications_owner_idx
  ON profiles.remote_applications (owner_user_id);
COMMENT ON TABLE profiles.remote_applications IS
  'Federation principals: external systems that authenticate by signing JWTs verified against their JWKS/public keys. Members of tenants with roles via polymorphic tenant_memberships.';

-- Backfill: every federation-bearing tenant_issuers row becomes a
-- remote_application. The remote_app slug reuses the owning tenant slug; the
-- owner_user_id reuses the tenant's owner (NULL for non-personal orgs). Issuer
-- is unique, so the first issuer per tenant wins; extras are dropped (a tenant
-- previously could carry many issuers, a remote_app is one principal/issuer).
DO $$
BEGIN
  IF to_regclass('profiles.tenant_issuers') IS NOT NULL THEN
    EXECUTE $sql$
      INSERT INTO profiles.remote_applications
        (slug, owner_user_id, issuer, jwks_uri, mode, public_keys, audiences, enabled, created_at, updated_at)
      SELECT DISTINCT ON (t.slug)
        t.slug, t.owner_user_id, ti.issuer,
        COALESCE(ti.jwks_uri, ''), ti.mode, ti.public_keys,
        ti.audiences, ti.enabled, ti.created_at, ti.updated_at
      FROM profiles.tenant_issuers ti
      JOIN profiles.tenants t ON t.id = ti.tenant_id AND t.deleted_at IS NULL
      ORDER BY t.slug, ti.created_at ASC
      ON CONFLICT (issuer) DO NOTHING
    $sql$;
  END IF;
END $$;

-- Make tenant_memberships POLYMORPHIC: a member is a user OR a remote_application.
-- Rename user_id -> member_id, drop the users FK (kind decides the referent),
-- add member_kind. Integrity per-kind is enforced by a trigger below.
ALTER TABLE profiles.tenant_memberships
  ADD COLUMN IF NOT EXISTS member_kind text NOT NULL DEFAULT 'user';

ALTER TABLE profiles.tenant_memberships DROP CONSTRAINT IF EXISTS tenant_memberships_user_id_fkey;
ALTER TABLE profiles.tenant_memberships DROP CONSTRAINT IF EXISTS tenant_memberships_tenant_id_user_id_key;
ALTER TABLE profiles.tenant_memberships RENAME COLUMN user_id TO member_id;

ALTER TABLE profiles.tenant_memberships
  DROP CONSTRAINT IF EXISTS tenant_memberships_member_kind_chk,
  ADD CONSTRAINT tenant_memberships_member_kind_chk
    CHECK (member_kind IN ('user', 'remote_application'));

-- Uniqueness now spans the principal kind.
DROP INDEX IF EXISTS profiles.tenant_memberships_user_id_idx;
CREATE INDEX IF NOT EXISTS tenant_memberships_member_idx
  ON profiles.tenant_memberships (member_id, member_kind)
  WHERE deleted_at IS NULL;
CREATE UNIQUE INDEX IF NOT EXISTS tenant_memberships_tenant_member_uidx
  ON profiles.tenant_memberships (tenant_id, member_id, member_kind);

-- Per-kind referential integrity (a polymorphic FK can't be a plain FK): the
-- referent must exist in the table the kind names.
CREATE OR REPLACE FUNCTION profiles.trg_tenant_membership_member_fk() RETURNS trigger
 LANGUAGE plpgsql
 AS $$
BEGIN
  IF NEW.member_kind = 'user' THEN
    IF NOT EXISTS (SELECT 1 FROM profiles.users WHERE id = NEW.member_id) THEN
      RAISE EXCEPTION 'tenant_memberships.member_id % is not a profiles.users row', NEW.member_id
        USING ERRCODE = 'foreign_key_violation';
    END IF;
  ELSIF NEW.member_kind = 'remote_application' THEN
    IF NOT EXISTS (SELECT 1 FROM profiles.remote_applications WHERE id = NEW.member_id) THEN
      RAISE EXCEPTION 'tenant_memberships.member_id % is not a profiles.remote_applications row', NEW.member_id
        USING ERRCODE = 'foreign_key_violation';
    END IF;
  END IF;
  RETURN NEW;
END;
$$;
DROP TRIGGER IF EXISTS tenant_membership_member_fk ON profiles.tenant_memberships;
CREATE TRIGGER tenant_membership_member_fk
  BEFORE INSERT OR UPDATE OF member_id, member_kind ON profiles.tenant_memberships
  FOR EACH ROW EXECUTE FUNCTION profiles.trg_tenant_membership_member_fk();

COMMENT ON COLUMN profiles.tenant_memberships.member_id IS 'Principal id; referent table named by member_kind.';
COMMENT ON COLUMN profiles.tenant_memberships.member_kind IS 'Principal kind: user | remote_application. One membership system serves both.';

-- Re-point tenant_subjects (the delegated END-USERS a remote_app vouches for —
-- NOT members) from tenant_id to remote_application_id. Backfill via the issuer:
-- a subject's tenant had exactly one issuer, now a remote_application.
-- Re-point tenant_subjects to remote_application_id (backfill via issuer).
ALTER TABLE profiles.tenant_subjects
  ADD COLUMN IF NOT EXISTS remote_application_id uuid REFERENCES profiles.remote_applications(id) ON DELETE CASCADE;

UPDATE profiles.tenant_subjects ts
SET remote_application_id = ra.id
FROM profiles.remote_applications ra
WHERE ts.remote_application_id IS NULL AND ra.issuer = ts.issuer;

-- Drop subjects we could not map (no surviving remote_application for their
-- issuer); they are re-touched on next use under the new principal.
DELETE FROM profiles.tenant_subjects WHERE remote_application_id IS NULL;

-- Swap the old tenant scoping for the new principal scoping.
ALTER TABLE profiles.tenant_subjects DROP CONSTRAINT IF EXISTS tenant_subjects_tenant_id_issuer_subject_key;
ALTER TABLE profiles.tenant_subjects DROP CONSTRAINT IF EXISTS delegated_users_tenant_id_issuer_subject_key;
DROP INDEX IF EXISTS profiles.tenant_subjects_tenant_idx;
ALTER TABLE profiles.tenant_subjects DROP CONSTRAINT IF EXISTS tenant_subjects_tenant_id_fkey;
ALTER TABLE profiles.tenant_subjects DROP CONSTRAINT IF EXISTS delegated_users_tenant_id_fkey;
ALTER TABLE profiles.tenant_subjects DROP COLUMN IF EXISTS tenant_id;
ALTER TABLE profiles.tenant_subjects ALTER COLUMN remote_application_id SET NOT NULL;

CREATE UNIQUE INDEX IF NOT EXISTS tenant_subjects_app_issuer_subject_uidx
  ON profiles.tenant_subjects (remote_application_id, issuer, subject);
CREATE INDEX IF NOT EXISTS tenant_subjects_app_idx
  ON profiles.tenant_subjects (remote_application_id);
COMMENT ON TABLE profiles.tenant_subjects IS
  'Delegated OIDC subjects a remote_application vouches for: opaque (remote_application_id, issuer, subject) tuples. Not members, not local users; their permissions ride on the token (#75).';

-- The org/tenants table sheds federation: tenant_issuers is now subsumed by
-- remote_applications. Drop it (data migrated above).
DROP TABLE IF EXISTS profiles.tenant_issuers;
