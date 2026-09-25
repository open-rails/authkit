-- parent: 3 sha256:8370ac20f35b38c3a89b793c01c069b4481dfe9b101f9a5ccd30454e8f40b412
-- Short-lived, single-use auth state shared by every replica: codes, tokens,
-- ceremonies, OIDC/SIWS state and attempt counters. Rows past expires_at are
-- invisible to reads and purged by the maintenance job.
CREATE TABLE ephemeral_kv (
    key text PRIMARY KEY,
    value bytea NOT NULL,
    expires_at timestamptz NOT NULL
);

CREATE INDEX ephemeral_kv_expires_at_idx ON ephemeral_kv (expires_at);
