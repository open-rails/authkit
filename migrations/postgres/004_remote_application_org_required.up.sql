-- #95: remote-applications are a pure ORG sub-resource (like api-keys). org_id
-- is now REQUIRED — there is NO org-less / "operator-managed" issuer. Every
-- issuer is org-bound, so it maps to exactly one merchant via its owning org and
-- the federation chain is sound (an issuer "attached to nothing" is rejected).

SET lock_timeout = '10s';

-- Drop any pre-existing org-less rows (the category no longer exists).
DELETE FROM profiles.remote_applications WHERE org_id IS NULL;

ALTER TABLE profiles.remote_applications ALTER COLUMN org_id SET NOT NULL;

COMMENT ON COLUMN profiles.remote_applications.org_id IS
  'REQUIRED controlling org (#95): remote-apps are org-nested like api-keys. No org-less/operator-managed issuer — every issuer is org-bound and maps to one merchant via its owning org.';
