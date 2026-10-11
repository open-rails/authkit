-- parent: 15 sha256:7ad442e483d42e059d63284e1835a9c81de6982561474e79b7100040030df73f
-- Agreements (#449): each version of a document a user accepted, append-only.
SET LOCAL lock_timeout = '10s';

CREATE TABLE user_agreements (
  user_id uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  key text NOT NULL CONSTRAINT ua_key_chk CHECK (key ~ '^[a-z0-9][a-z0-9_-]{0,63}$'),
  version text NOT NULL CONSTRAINT ua_version_chk CHECK (length(version) BETWEEN 1 AND 64),
  accepted_at timestamptz NOT NULL DEFAULT now(),
  channel text NOT NULL CONSTRAINT ua_channel_chk CHECK (channel IN ('registration', 'account', 'host')),
  ip_addr inet,
  user_agent text,
  PRIMARY KEY (user_id, key, version)
);
COMMENT ON TABLE user_agreements IS
  'Each version of a declared document (Config.Agreements) a user accepted: when, where and from which client. Never updated; purged with the account.';
