-- parent: 16 sha256:97140311129487977c7fe845c39a75da58de7c9a2513ba1ef5e262fc65ba4153
-- Group OAuth clients (#450): OAuth clients a group registers at run time
-- (RFC 7591 metadata), and each user's consent to them.
SET LOCAL lock_timeout = '10s';

CREATE TABLE group_oauth_clients (
  client_id text PRIMARY KEY CONSTRAINT goc_client_id_chk CHECK (client_id ~ '^goc_[a-z2-7]{26}$'),
  permission_group_id uuid NOT NULL REFERENCES permission_groups(id) ON DELETE CASCADE,
  client_name text NOT NULL CONSTRAINT goc_name_chk CHECK (length(client_name) BETWEEN 1 AND 128),
  logo_uri text CONSTRAINT goc_logo_chk CHECK (logo_uri <> ''),
  client_uri text CONSTRAINT goc_client_uri_chk CHECK (client_uri <> ''),
  policy_uri text CONSTRAINT goc_policy_chk CHECK (policy_uri <> ''),
  tos_uri text CONSTRAINT goc_tos_chk CHECK (tos_uri <> ''),
  redirect_uris text[] NOT NULL CONSTRAINT goc_redirects_chk CHECK (cardinality(redirect_uris) BETWEEN 1 AND 10),
  post_logout_redirect_uris text[] NOT NULL DEFAULT '{}' CONSTRAINT goc_logout_redirects_chk CHECK (cardinality(post_logout_redirect_uris) <= 10),
  token_endpoint_auth_method text NOT NULL CONSTRAINT goc_auth_method_chk CHECK (token_endpoint_auth_method IN ('private_key_jwt', 'client_secret_basic', 'none')),
  secret_hash text,
  jwks_uri text,
  scopes text[] NOT NULL CONSTRAINT goc_scopes_chk CHECK ('openid' = ANY(scopes)),
  backchannel_logout_uri text CONSTRAINT goc_backchannel_chk CHECK (backchannel_logout_uri <> ''),
  disabled_at timestamptz,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  CONSTRAINT goc_secret_chk CHECK ((token_endpoint_auth_method = 'client_secret_basic') = (secret_hash IS NOT NULL)),
  CONSTRAINT goc_jwks_chk CHECK ((token_endpoint_auth_method = 'private_key_jwt') = (jwks_uri IS NOT NULL))
);
CREATE INDEX group_oauth_clients_group_idx ON group_oauth_clients (permission_group_id);
COMMENT ON TABLE group_oauth_clients IS
  'OAuth clients groups register at run time (RFC 7591 metadata): third-party clients whose users consent per scope, and whose tokens act only in their group. Deleted with the group.';

CREATE TABLE oauth_consents (
  user_id uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  client_id text NOT NULL REFERENCES group_oauth_clients(client_id) ON DELETE CASCADE,
  scopes text[] NOT NULL,
  granted_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (user_id, client_id)
);
CREATE INDEX oauth_consents_client_idx ON oauth_consents (client_id);
COMMENT ON TABLE oauth_consents IS
  'Each user''s consent to a group OAuth client: the scopes it may ask without asking again. Withdrawing it ends the client''s refresh tokens for the user.';

-- The OAuth client a client or consent event names, and the document an
-- agreement event names.
ALTER TABLE account_events
  ADD COLUMN client_id text NOT NULL DEFAULT '',
  ADD COLUMN agreement text NOT NULL DEFAULT '';
