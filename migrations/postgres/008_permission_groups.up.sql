-- #111: generalize `org` → permission-group. N-level resource-scoped RBAC with
-- single-parent inheritance. HARD CUT, greenfield (no production data to carry):
-- `org` stops being a built-in entirely; `platform` collapses into the single
-- built-in `root` permission-group; every other group is an app-declared TYPE.
--
--   * permission_groups        replaces  orgs            (typed, single-parent)
--   * group_role_assignments   replaces  org_memberships + platform_user_roles
--   * group_custom_roles       replaces  org_roles/org_role_permissions (opt-in only;
--                                        catalog roles now live in core.Config, not the DB)
--   * group_invites            replaces  org_invites
--   * remote_applications / service_tokens re-nest org_id -> permission_group_id
--
-- Catalog role->permission mappings move OUT of the database into the app's
-- declared per-type catalog (core.Config); only OPT-IN custom roles persist here.

SET lock_timeout = '10s';
SET statement_timeout = '300s';

-- =============================================================================
-- 1. Containment schema as data: the allowed parent TYPE(s) per type. A plain
--    FK proves a parent EXISTS, not that it is the right TYPE — so the shape is
--    enforced by a trigger reading this table. `root` has NO row (parentless).
-- =============================================================================
CREATE TABLE IF NOT EXISTS profiles.group_type_parents (
  type                text NOT NULL,
  allowed_parent_type text NOT NULL,
  created_at          timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (type, allowed_parent_type),
  CONSTRAINT gtp_type_format_chk CHECK (type ~ '^[a-z][a-z0-9-]*$'),
  CONSTRAINT gtp_parent_format_chk CHECK (allowed_parent_type ~ '^[a-z][a-z0-9-]*$'),
  CONSTRAINT gtp_not_self_chk CHECK (type <> allowed_parent_type),
  CONSTRAINT gtp_root_has_no_parent_chk CHECK (type <> 'root')
);
COMMENT ON TABLE profiles.group_type_parents IS
  'The declared containment schema (#111): which parent TYPE(s) each group type allows. The app seeds it from core.Config at bootstrap; the permission_group containment trigger enforces it. root is absent (parentless singleton).';

-- =============================================================================
-- 2. permission_groups: the typed container that holds assignments and has a
--    SINGLE parent (replaces orgs). Addressed by (type, resource_ref); the id
--    is INTERNAL-only (never in a request/response).
-- =============================================================================
CREATE TABLE IF NOT EXISTS profiles.permission_groups (
  id           uuid PRIMARY KEY DEFAULT uuidv7(),
  type         text NOT NULL,
  parent_id    uuid REFERENCES profiles.permission_groups(id) ON DELETE CASCADE,
  parent_type  text,                                   -- denormalized parent.type for the containment trigger
  resource_ref text,                                   -- (type, resource_ref) is the API addressing key
  metadata     jsonb NOT NULL DEFAULT '{}'::jsonb,
  created_at   timestamptz NOT NULL DEFAULT now(),
  updated_at   timestamptz NOT NULL DEFAULT now(),
  deleted_at   timestamptz,
  CONSTRAINT pg_type_format_chk CHECK (type ~ '^[a-z][a-z0-9-]*$'),
  -- root is the singleton parentless group; every non-root group has a typed parent.
  CONSTRAINT pg_root_parentless_chk CHECK (
    (type = 'root' AND parent_id IS NULL AND parent_type IS NULL)
    OR (type <> 'root' AND parent_id IS NOT NULL AND parent_type IS NOT NULL)
  )
);
-- A resource is addressed by (type, resource_ref) — unique among live groups.
CREATE UNIQUE INDEX IF NOT EXISTS permission_groups_type_resource_uidx
  ON profiles.permission_groups (type, resource_ref)
  WHERE resource_ref IS NOT NULL AND deleted_at IS NULL;
-- Exactly one live root group per deployment (the singleton).
CREATE UNIQUE INDEX IF NOT EXISTS permission_groups_singleton_root_uidx
  ON profiles.permission_groups ((type = 'root'))
  WHERE type = 'root' AND deleted_at IS NULL;
CREATE INDEX IF NOT EXISTS permission_groups_parent_idx
  ON profiles.permission_groups (parent_id) WHERE parent_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS permission_groups_type_idx
  ON profiles.permission_groups (type) WHERE deleted_at IS NULL;
COMMENT ON COLUMN profiles.permission_groups.resource_ref IS
  'Links the group to its app resource AND is the API addressing key: a route (persona, resource-id) resolves to the group via (type, resource_ref). The group id is INTERNAL-only.';

-- Containment backstop: parent_type must match the actual parent row's type AND
-- be a declared allowed parent for the child type. The app layer also validates
-- (clear errors); this makes off-shape rows impossible even via raw SQL.
CREATE OR REPLACE FUNCTION profiles.trg_permission_group_containment() RETURNS trigger
LANGUAGE plpgsql AS $$
DECLARE
  actual_parent_type text;
BEGIN
  IF NEW.type = 'root' THEN
    RETURN NEW; -- parentless; enforced by pg_root_parentless_chk
  END IF;
  SELECT type INTO actual_parent_type FROM profiles.permission_groups WHERE id = NEW.parent_id;
  IF actual_parent_type IS NULL THEN
    RAISE EXCEPTION 'permission_groups.parent_id % does not exist', NEW.parent_id
      USING ERRCODE = 'foreign_key_violation';
  END IF;
  IF actual_parent_type <> NEW.parent_type THEN
    RAISE EXCEPTION 'permission_groups.parent_type % does not match parent''s actual type %',
      NEW.parent_type, actual_parent_type USING ERRCODE = 'check_violation';
  END IF;
  IF NOT EXISTS (
    SELECT 1 FROM profiles.group_type_parents
    WHERE type = NEW.type AND allowed_parent_type = NEW.parent_type
  ) THEN
    RAISE EXCEPTION 'a % group may not have a % parent (not in the containment schema)',
      NEW.type, NEW.parent_type USING ERRCODE = 'check_violation';
  END IF;
  RETURN NEW;
END;
$$;
DROP TRIGGER IF EXISTS permission_group_containment ON profiles.permission_groups;
CREATE TRIGGER permission_group_containment
  BEFORE INSERT OR UPDATE OF type, parent_id, parent_type ON profiles.permission_groups
  FOR EACH ROW EXECUTE FUNCTION profiles.trg_permission_group_containment();

-- =============================================================================
-- 3. group_role_assignments: who holds which role in a group (replaces
--    org_memberships AND platform_user_roles — root authority is just an
--    assignment in the root group). Polymorphic subject (user | remote_app).
--    The role NAME resolves to permissions via the app catalog (core.Config) or
--    a group_custom_role; it is NOT FK-bound to a DB role table anymore.
-- =============================================================================
CREATE TABLE IF NOT EXISTS profiles.group_role_assignments (
  group_id     uuid NOT NULL REFERENCES profiles.permission_groups(id) ON DELETE CASCADE,
  subject_id   uuid NOT NULL,
  subject_kind text NOT NULL DEFAULT 'user',
  role         text NOT NULL,
  created_at   timestamptz NOT NULL DEFAULT now(),
  updated_at   timestamptz NOT NULL DEFAULT now(),
  deleted_at   timestamptz,
  CONSTRAINT gra_subject_kind_chk CHECK (subject_kind IN ('user', 'remote_application')),
  CONSTRAINT gra_role_format_chk CHECK (role ~ '^[a-z][a-z0-9-]*$')
);
CREATE UNIQUE INDEX IF NOT EXISTS gra_group_subject_role_uidx
  ON profiles.group_role_assignments (group_id, subject_id, subject_kind, role)
  WHERE deleted_at IS NULL;
CREATE INDEX IF NOT EXISTS gra_subject_idx
  ON profiles.group_role_assignments (subject_id, subject_kind) WHERE deleted_at IS NULL;
CREATE INDEX IF NOT EXISTS gra_group_idx
  ON profiles.group_role_assignments (group_id) WHERE deleted_at IS NULL;

-- Polymorphic subject FK (mirrors the retired org_membership trigger).
CREATE OR REPLACE FUNCTION profiles.trg_group_assignment_subject_fk() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
  IF NEW.subject_kind = 'user' THEN
    IF NOT EXISTS (SELECT 1 FROM profiles.users WHERE id = NEW.subject_id) THEN
      RAISE EXCEPTION 'group_role_assignments.subject_id % is not a profiles.users row', NEW.subject_id
        USING ERRCODE = 'foreign_key_violation';
    END IF;
  ELSIF NEW.subject_kind = 'remote_application' THEN
    IF NOT EXISTS (SELECT 1 FROM profiles.remote_applications WHERE id = NEW.subject_id) THEN
      RAISE EXCEPTION 'group_role_assignments.subject_id % is not a profiles.remote_applications row', NEW.subject_id
        USING ERRCODE = 'foreign_key_violation';
    END IF;
  END IF;
  RETURN NEW;
END;
$$;
DROP TRIGGER IF EXISTS group_assignment_subject_fk ON profiles.group_role_assignments;
CREATE TRIGGER group_assignment_subject_fk
  BEFORE INSERT OR UPDATE OF subject_id, subject_kind ON profiles.group_role_assignments
  FOR EACH ROW EXECUTE FUNCTION profiles.trg_group_assignment_subject_fk();

-- =============================================================================
-- 4. group_custom_roles: per-group custom role bundles. ONLY used by types whose
--    catalog opts into AllowCustomRoles; the app enforces that + validates each
--    grant pattern before insert. Catalog (built-in) roles are NOT stored here.
-- =============================================================================
CREATE TABLE IF NOT EXISTS profiles.group_custom_roles (
  group_id    uuid NOT NULL REFERENCES profiles.permission_groups(id) ON DELETE CASCADE,
  role        text NOT NULL,
  permissions text[] NOT NULL DEFAULT '{}',
  created_at  timestamptz NOT NULL DEFAULT now(),
  updated_at  timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (group_id, role),
  CONSTRAINT gcr_role_format_chk CHECK (role ~ '^[a-z][a-z0-9-]*$')
);

-- =============================================================================
-- 5. group_invites: the human invite flow (replaces org_invites). role resolves
--    via the catalog/custom roles, not a DB FK.
-- =============================================================================
CREATE TABLE IF NOT EXISTS profiles.group_invites (
  id         uuid PRIMARY KEY DEFAULT uuidv7(),
  group_id   uuid NOT NULL REFERENCES profiles.permission_groups(id) ON DELETE CASCADE,
  user_id    uuid NOT NULL REFERENCES profiles.users(id) ON DELETE CASCADE,
  invited_by uuid NOT NULL REFERENCES profiles.users(id) ON DELETE RESTRICT,
  role       text NOT NULL,
  status     text NOT NULL DEFAULT 'pending',
  expires_at timestamptz,
  acted_at   timestamptz,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  deleted_at timestamptz,
  CONSTRAINT group_invites_status_chk CHECK (status IN ('pending', 'accepted', 'declined', 'revoked', 'expired')),
  CONSTRAINT group_invites_role_format_chk CHECK (role ~ '^[a-z][a-z0-9-]*$')
);
CREATE INDEX IF NOT EXISTS group_invites_group_idx ON profiles.group_invites (group_id) WHERE deleted_at IS NULL;
CREATE INDEX IF NOT EXISTS group_invites_user_idx ON profiles.group_invites (user_id) WHERE deleted_at IS NULL;
CREATE UNIQUE INDEX IF NOT EXISTS group_invites_pending_uidx
  ON profiles.group_invites (group_id, user_id)
  WHERE status = 'pending' AND deleted_at IS NULL;

-- =============================================================================
-- 6. HARD CUT: drop the org RBAC + platform planes. CASCADE strips the org FKs
--    off remote_applications/service_tokens (leaving their columns to re-nest).
-- =============================================================================
DROP TRIGGER IF EXISTS org_membership_member_fk ON profiles.org_memberships;
DROP FUNCTION IF EXISTS profiles.trg_org_membership_member_fk();

DROP TABLE IF EXISTS profiles.platform_user_roles CASCADE;
DROP TABLE IF EXISTS profiles.platform_role_permissions CASCADE;
DROP TABLE IF EXISTS profiles.platform_roles CASCADE;

DROP TABLE IF EXISTS profiles.org_invites CASCADE;
DROP TABLE IF EXISTS profiles.org_renames CASCADE;
DROP TABLE IF EXISTS profiles.org_memberships CASCADE;
DROP TABLE IF EXISTS profiles.org_role_permissions CASCADE;
DROP TABLE IF EXISTS profiles.org_roles CASCADE;
DROP TABLE IF EXISTS profiles.orgs CASCADE;

-- =============================================================================
-- 7. Re-nest credentials under permission_groups. The org FKs were dropped by
--    the CASCADE above; the org_id columns remain (now unconstrained) and are
--    renamed + re-pointed. service_tokens.role keeps its column (now a catalog/
--    custom role of the group's TYPE, validated by the app — no DB role FK).
-- =============================================================================
ALTER TABLE profiles.remote_applications RENAME COLUMN org_id TO permission_group_id;
ALTER TABLE profiles.remote_applications
  ADD CONSTRAINT remote_applications_group_fkey
  FOREIGN KEY (permission_group_id) REFERENCES profiles.permission_groups(id);
ALTER INDEX profiles.remote_applications_org_idx RENAME TO remote_applications_group_idx;
COMMENT ON COLUMN profiles.remote_applications.permission_group_id IS
  'REQUIRED controlling permission-group (#111): remote-apps are group-nested. Authority comes from group_role_assignments (subject_kind=remote_application) + the parent walk.';

ALTER TABLE profiles.service_tokens RENAME COLUMN org_id TO permission_group_id;
ALTER TABLE profiles.service_tokens
  ADD CONSTRAINT service_tokens_group_fkey
  FOREIGN KEY (permission_group_id) REFERENCES profiles.permission_groups(id) ON DELETE CASCADE;
ALTER INDEX profiles.service_tokens_org_idx RENAME TO service_tokens_group_idx;
ALTER INDEX profiles.service_tokens_org_role_idx RENAME TO service_tokens_group_role_idx;
COMMENT ON COLUMN profiles.service_tokens.role IS
  'The single catalog/custom role this API key holds within its permission-group. Effective permissions resolve from the group TYPE catalog (core.Config) or a group_custom_role at use time (#111). Resource-scope is a separate binding (service_token_resources).';
