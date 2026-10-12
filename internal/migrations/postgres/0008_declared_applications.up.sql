-- A remote application declared in a deployment's Config.RemoteApplications
-- records that deployment, which disables it once it is no longer declared.
SET LOCAL lock_timeout = '10s';

ALTER TABLE remote_applications ADD COLUMN declared_by text;
COMMENT ON COLUMN remote_applications.declared_by IS
  'The Token.Issuer of the app whose Config.RemoteApplications declares it; NULL = registered through an operation.';
