-- ak#278: public keys held by native clients. Private keys never enter AuthKit.
CREATE TABLE IF NOT EXISTS profiles.user_device_keys (
  id           uuid PRIMARY KEY DEFAULT uuidv7(),
  user_id      uuid NOT NULL REFERENCES profiles.users(id) ON DELETE CASCADE,
  public_key   bytea NOT NULL UNIQUE,
  label        text,
  created_at   timestamptz NOT NULL DEFAULT now(),
  last_used_at timestamptz,
  revoked_at   timestamptz,
  CONSTRAINT user_device_keys_public_key_length_chk CHECK (octet_length(public_key) = 32),
  CONSTRAINT user_device_keys_label_length_chk CHECK (label IS NULL OR char_length(label) <= 128)
);

CREATE INDEX IF NOT EXISTS user_device_keys_user_active_idx
  ON profiles.user_device_keys (user_id)
  WHERE revoked_at IS NULL;

COMMENT ON TABLE profiles.user_device_keys IS
  'Ed25519 public keys for native clients. Revoked rows remain tombstones and cannot be re-enrolled.';
