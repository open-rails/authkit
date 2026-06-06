-- Resource-scoped Organization Access Tokens (authkit #52).
--
-- Resource scopes are opaque host-defined Kind/ID pairs. AuthKit stores and
-- resolves them beside the OAT but does not interpret their semantics.
CREATE TABLE IF NOT EXISTS profiles.org_access_token_resources (
  token_id    uuid NOT NULL REFERENCES profiles.org_access_tokens(id) ON DELETE CASCADE,
  kind        text NOT NULL,
  resource_id text NOT NULL,
  created_at  timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (token_id, kind, resource_id),
  CONSTRAINT org_access_token_resources_kind_len_chk CHECK (char_length(kind) BETWEEN 1 AND 128),
  CONSTRAINT org_access_token_resources_resource_id_len_chk CHECK (char_length(resource_id) BETWEEN 1 AND 128)
);

CREATE INDEX IF NOT EXISTS org_access_token_resources_token_idx
  ON profiles.org_access_token_resources (token_id);
