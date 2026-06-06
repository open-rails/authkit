-- Resource-scoped Service Tokens (authkit #52).
--
-- Older databases may have already recorded migration 001 from before
-- profiles.service_tokens was added to the compacted baseline. Keep this
-- numbered migration self-contained so those databases can still advance.
CREATE TABLE IF NOT EXISTS profiles.service_tokens (
  id           uuid PRIMARY KEY DEFAULT uuidv7(),
  tenant_id    uuid NOT NULL REFERENCES profiles.tenants(id) ON DELETE CASCADE,
  key_id       text NOT NULL UNIQUE,
  secret_hash  bytea NOT NULL,
  name         text NOT NULL,
  created_by   uuid REFERENCES profiles.users(id) ON DELETE SET NULL,
  created_at   timestamptz NOT NULL DEFAULT now(),
  last_used_at timestamptz,
  expires_at   timestamptz,
  revoked_at   timestamptz,
  CONSTRAINT service_tokens_name_len_chk CHECK (char_length(name) BETWEEN 1 AND 128)
);

CREATE INDEX IF NOT EXISTS service_tokens_tenant_idx
  ON profiles.service_tokens (tenant_id);

-- Resource scopes are opaque host-defined Kind/ID pairs. AuthKit stores and
-- resolves them beside the service token but does not interpret their semantics.
CREATE TABLE IF NOT EXISTS profiles.service_token_resources (
  token_id    uuid NOT NULL REFERENCES profiles.service_tokens(id) ON DELETE CASCADE,
  kind        text NOT NULL,
  resource_id text NOT NULL,
  created_at  timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (token_id, kind, resource_id),
  CONSTRAINT service_token_resources_kind_len_chk CHECK (char_length(kind) BETWEEN 1 AND 128),
  CONSTRAINT service_token_resources_resource_id_len_chk CHECK (char_length(resource_id) BETWEEN 1 AND 128)
);

CREATE INDEX IF NOT EXISTS service_token_resources_token_idx
  ON profiles.service_token_resources (token_id);
