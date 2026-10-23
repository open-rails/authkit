-- Group API keys belong to the group. Their creator is audit information;
-- leaving the organization must not take its automation down.
ALTER TABLE api_keys DROP CONSTRAINT api_keys_created_by_fkey;
ALTER TABLE api_keys ADD CONSTRAINT api_keys_created_by_fkey
    FOREIGN KEY (created_by) REFERENCES users(id) ON DELETE SET NULL;
COMMENT ON COLUMN api_keys.created_by IS 'Audit: creating user, or NULL for system issuance or a purged creator. Does not own the key.';

-- A personal token is a separate credential, bounded by a live user's
-- authority. It is never an organization key or an interactive sign-in.
CREATE TABLE personal_access_tokens (
    id uuid PRIMARY KEY DEFAULT uuidv7(),
    owner_user_id uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    permission_group_id uuid NOT NULL REFERENCES permission_groups(id) ON DELETE CASCADE,
    catalog_issuer text NOT NULL,
    lookup_id text NOT NULL UNIQUE,
    secret_hash bytea NOT NULL,
    name text NOT NULL CHECK (char_length(name) BETWEEN 1 AND 128),
    permissions text[] NOT NULL CHECK (cardinality(permissions) BETWEEN 1 AND 100),
    created_at timestamptz NOT NULL DEFAULT now(),
    last_used_at timestamptz,
    expires_at timestamptz NOT NULL,
    revoked_at timestamptz
);
CREATE INDEX personal_access_tokens_owner_idx ON personal_access_tokens(owner_user_id, catalog_issuer, id DESC);
CREATE INDEX personal_access_tokens_group_idx ON personal_access_tokens(permission_group_id);
CREATE INDEX personal_access_tokens_terminal_idx ON personal_access_tokens(LEAST(revoked_at, expires_at), id);
