-- Individual policy survives role changes and is enforced at authentication.
ALTER TABLE users ADD COLUMN mfa_required boolean NOT NULL DEFAULT false;
COMMENT ON COLUMN users.mfa_required IS 'Administrator-required MFA; enrollment may be completed after the policy is set';
