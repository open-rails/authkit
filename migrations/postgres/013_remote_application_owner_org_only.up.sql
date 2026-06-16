-- Remote applications are org-owned or unowned/bootstrap-managed.
-- Users are not owners for issuer trust roots.

SET lock_timeout = '10s';
SET statement_timeout = '300s';

DROP INDEX IF EXISTS profiles.remote_applications_owner_idx;

ALTER TABLE profiles.remote_applications
  DROP CONSTRAINT IF EXISTS remote_applications_owner_user_id_fkey;

ALTER TABLE profiles.remote_applications
  DROP COLUMN IF EXISTS owner_user_id;

COMMENT ON COLUMN profiles.remote_applications.org_id IS
  'Optional controlling org. NULL = bootstrap/operator-managed issuer with no AuthKit user/org owner; SET = org-controlled issuer managed through org RBAC.';
