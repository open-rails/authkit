-- #75: the generic definition registry behind REFERENCE-mode delegated-token
-- attributes. A remote_application registers (key, version) -> definition; a
-- platform resolves the reference back to its definition. The definition is an
-- OPAQUE JSON doc — AuthKit stores and serves it but NEVER interprets it (same
-- agnosticism as the token `attributes` bag). INLINE mode needs no storage.

SET lock_timeout = '10s';
SET statement_timeout = '300s';

CREATE TABLE IF NOT EXISTS profiles.remote_application_attribute_defs (
  remote_application_id uuid NOT NULL REFERENCES profiles.remote_applications(id) ON DELETE CASCADE,
  key         text NOT NULL,
  version     integer NOT NULL DEFAULT 1,
  definition  jsonb NOT NULL,
  created_at  timestamptz NOT NULL DEFAULT now(),
  updated_at  timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (remote_application_id, key, version),
  CONSTRAINT raad_key_format_chk CHECK (
    char_length(key) BETWEEN 1 AND 128
    AND key ~ '^[a-zA-Z0-9:._-]+$'
  ),
  CONSTRAINT raad_version_chk CHECK (version >= 1)
);
CREATE INDEX IF NOT EXISTS raad_app_key_idx
  ON profiles.remote_application_attribute_defs (remote_application_id, key, version DESC);
COMMENT ON TABLE profiles.remote_application_attribute_defs IS
  'REFERENCE-mode attribute definitions: (remote_application_id, key, version) -> opaque definition jsonb. AuthKit transports + serves, never interprets (#75).';
