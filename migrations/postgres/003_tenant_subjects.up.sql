-- Rename profiles.delegated_users -> profiles.tenant_subjects.
--
-- The rows are not users: they are opaque (tenant_id, issuer, subject) OIDC
-- subject tuples recording which delegated subjects have been accepted under
-- each tenant. The new name matches the claim that carries the delegated subject
-- (`delegated_sub`) and the equivalent table on the resource-server side
-- (e.g. openrails billing.tenant_subjects).
ALTER TABLE IF EXISTS profiles.delegated_users RENAME TO tenant_subjects;
ALTER INDEX IF EXISTS profiles.delegated_users_tenant_idx RENAME TO tenant_subjects_tenant_idx;
COMMENT ON TABLE profiles.tenant_subjects IS
  'Delegated OIDC subjects accepted per tenant: opaque (tenant_id, issuer, subject) tuples with first/last-seen timestamps. Not local users.';
