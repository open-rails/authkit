-- parent: 5 sha256:59294d27b4e878380a12e155e1666a37252a9b7ce80f53ff146ad65589ebab74
-- A credential never outlives its issuer. The operator issues invitations with
-- no inviter, as it already issues API keys with no creator; a purged
-- creator's keys go with the account instead of becoming creator-less. Keys an
-- earlier purge left creator-less were never operator-issued, so they die now.
ALTER TABLE group_invite_links ALTER COLUMN invited_by DROP NOT NULL;
ALTER TABLE account_registration_invites ALTER COLUMN invited_by DROP NOT NULL;
UPDATE api_keys SET revoked_at = now() WHERE created_by IS NULL AND revoked_at IS NULL;
ALTER TABLE api_keys
  DROP CONSTRAINT api_keys_created_by_fkey,
  ADD CONSTRAINT api_keys_created_by_fkey FOREIGN KEY (created_by) REFERENCES users(id) ON DELETE CASCADE;
-- Issuer lookups: the credential sweep of one account, and purge cascades.
CREATE INDEX api_keys_created_by_idx ON api_keys (created_by);
CREATE INDEX group_invite_links_invited_by_idx ON group_invite_links (invited_by);
CREATE INDEX account_registration_invites_invited_by_idx ON account_registration_invites (invited_by);
COMMENT ON COLUMN api_keys.created_by IS 'The issuing user; NULL = issued by the operator.';
COMMENT ON COLUMN group_invite_links.invited_by IS 'The issuing user; NULL = issued by the operator.';
COMMENT ON COLUMN account_registration_invites.invited_by IS 'The issuing user; NULL = issued by the operator.';

-- The role catalog whose credential sweep last ran. New re-checks every live
-- credential against its creator's authority when the catalog changes.
CREATE TABLE role_catalog_state (
  singleton boolean PRIMARY KEY DEFAULT true CHECK (singleton),
  fingerprint text NOT NULL,
  swept_at timestamptz NOT NULL DEFAULT now()
);
