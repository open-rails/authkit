-- parent: 11 sha256:4e4adf56e47b117c1a83eee1b967d39f52895749b029381aad6cce9d5b2f16dd
-- v1 drops signed documents, application self-registration and custom roles.
DROP TABLE signed_documents;
DROP TABLE group_custom_roles;

-- Remote applications keep an issuer, keys and a trust root: the system
-- (manual) or a group credentials manager (user). Domain-proven applications
-- become system-controlled.
UPDATE remote_applications SET trust_root = 'manual' WHERE trust_root = 'domain';
ALTER TABLE remote_applications
  DROP CONSTRAINT remote_applications_trust_root_chk,
  ADD CONSTRAINT remote_applications_trust_root_chk CHECK (trust_root IN ('manual', 'user')),
  DROP COLUMN display_name,
  DROP COLUMN tier,
  DROP COLUMN domain,
  DROP COLUMN document_endpoint,
  DROP COLUMN root_verified_at;
COMMENT ON COLUMN remote_applications.trust_root IS
  'What changes the keys: manual (the system) | user (a credentials manager of the controlling group). Never the keypair alone.';
COMMENT ON COLUMN remote_applications.registered_by IS 'The user who supplied the keys of a group registration; NULL = the operator.';
