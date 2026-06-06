-- Service-token permission assignments.
CREATE TABLE IF NOT EXISTS profiles.service_token_permissions (
  service_token_id uuid NOT NULL REFERENCES profiles.service_tokens(id) ON DELETE CASCADE,
  permission       text NOT NULL,
  created_at       timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (service_token_id, permission),
  CONSTRAINT service_token_permissions_perm_len_chk CHECK (char_length(permission) BETWEEN 1 AND 128)
);

CREATE INDEX IF NOT EXISTS service_token_permissions_token_idx
  ON profiles.service_token_permissions (service_token_id);

DO $$
BEGIN
  IF EXISTS (
    SELECT 1
    FROM information_schema.columns
    WHERE table_schema = 'profiles'
      AND table_name = 'service_tokens'
      AND column_name = 'permissions'
  ) THEN
    EXECUTE '
      INSERT INTO profiles.service_token_permissions (service_token_id, permission)
      SELECT id, unnest(permissions)
      FROM profiles.service_tokens
      ON CONFLICT DO NOTHING
    ';
  END IF;
END $$;

ALTER TABLE profiles.service_tokens
  DROP COLUMN IF EXISTS permissions;
