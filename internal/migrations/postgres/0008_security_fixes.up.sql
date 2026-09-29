-- parent: 6 sha256:06240f8684a9b78945c8f99c89cc60c46f3b355709f31f75b201c84acf1e5585
-- A sensitive action on an account with a second factor needs that factor
-- within the freshness window; a password re-auth never refreshes it. Sessions
-- that signed in with MFA proved it when they were created.
ALTER TABLE refresh_sessions ADD COLUMN mfa_authenticated_at timestamptz;
UPDATE refresh_sessions SET mfa_authenticated_at = created_at
 WHERE 'mfa' = ANY(auth_methods) AND revoked_at IS NULL;

-- A device key stands in for a second factor only when its enrollment proved one.
ALTER TABLE user_device_keys ADD COLUMN mfa_proven_at timestamptz;

-- A group-registered application is a credential of the user who supplied its
-- keys: its roles never outlive that user's authority. Operator and domain
-- registrations record no registrar. Group registrations from before this
-- migration have none either and confer nothing until they are re-registered.
ALTER TABLE remote_applications ADD COLUMN registered_by uuid REFERENCES users(id) ON DELETE SET NULL;
CREATE INDEX remote_applications_registered_by_idx ON remote_applications (registered_by);
COMMENT ON COLUMN remote_applications.registered_by IS 'The user who supplied the keys of a group registration; NULL = operator or domain.';

-- Only an account that deleted itself may restore itself by signing in.
ALTER TABLE account_deletions ADD COLUMN deleted_by uuid;
COMMENT ON COLUMN account_deletions.deleted_by IS 'The user who deleted the account; NULL = the operator.';
