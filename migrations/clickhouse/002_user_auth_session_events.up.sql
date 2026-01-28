-- AuthKit Analytics (ClickHouse)
-- Session lifecycle events only (no per-access-token mint telemetry).

-- Drop legacy tables/views (no data preservation/backfill; new deployments start empty).
DROP TABLE IF EXISTS mv_user_last_seen_from_refreshes {{ON_CLUSTER}};
DROP TABLE IF EXISTS mv_user_last_seen_from_logins {{ON_CLUSTER}};
DROP TABLE IF EXISTS user_last_seen_current {{ON_CLUSTER}};
DROP TABLE IF EXISTS user_auth_refreshes {{ON_CLUSTER}};
DROP TABLE IF EXISTS user_auth_logins {{ON_CLUSTER}};

-- Unified session lifecycle event stream.
CREATE TABLE IF NOT EXISTS user_auth_session_events {{ON_CLUSTER}} (
    occurred_at DateTime64(3, 'UTC'),
    issuer LowCardinality(String),
    user_id String,
    session_id String,
    event LowCardinality(String), -- session_created | session_revoked
    method LowCardinality(Nullable(String)), -- e.g. password_login | oidc_login | solana_login | ...
    reason LowCardinality(Nullable(String)), -- e.g. logout | admin_revoke | password_change | evicted | ...
    ip_addr Nullable(String),
    user_agent Nullable(String),
    version DateTime64(3, 'UTC') DEFAULT now64(3)
) ENGINE = ReplicatedReplacingMergeTree('/clickhouse/tables/{database}/{table}', '{replica}', version)
ORDER BY (issuer, user_id, session_id, occurred_at, event)
SETTINGS index_granularity = 8192;

