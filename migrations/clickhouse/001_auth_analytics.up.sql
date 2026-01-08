-- AuthKit Analytics Tables for ClickHouse
-- Tracks user authentication events (logins, token refreshes, last seen)
-- All tables use ReplicatedReplacingMergeTree for cluster replication and deduplication

-- Login events: refresh token issued at login
CREATE TABLE IF NOT EXISTS user_auth_logins {{ON_CLUSTER}} (
    occurred_at DateTime('UTC'),
    user_id String,
    method LowCardinality(String), -- password_login | oidc_login
    ip_addr Nullable(String),
    user_agent Nullable(String),
    version DateTime('UTC') DEFAULT now()
) ENGINE = ReplicatedReplacingMergeTree('/clickhouse/tables/{database}/{table}', '{replica}', version)
ORDER BY (user_id, occurred_at, method)
SETTINGS index_granularity = 8192;

-- Refresh events: ID token issued via refresh token
CREATE TABLE IF NOT EXISTS user_auth_refreshes {{ON_CLUSTER}} (
    occurred_at DateTime('UTC'),
    user_id String,
    ip_addr Nullable(String),
    user_agent Nullable(String),
    version DateTime('UTC') DEFAULT now()
) ENGINE = ReplicatedReplacingMergeTree('/clickhouse/tables/{database}/{table}', '{replica}', version)
ORDER BY (user_id, occurred_at)
SETTINGS index_granularity = 8192;

-- Current snapshot: last time a user obtained a token (login or refresh)
CREATE TABLE IF NOT EXISTS user_last_seen_current {{ON_CLUSTER}} (
    user_id String,
    last_seen DateTime('UTC') DEFAULT now(),
    ip_addr Nullable(String),
    user_agent Nullable(String),
    version DateTime('UTC') DEFAULT now()
) ENGINE = ReplicatedReplacingMergeTree('/clickhouse/tables/{database}/{table}', '{replica}', version)
ORDER BY (user_id)
SETTINGS index_granularity = 8192;

-- Materialized view: automatically populate user_last_seen_current from refresh events
CREATE MATERIALIZED VIEW IF NOT EXISTS mv_user_last_seen_from_refreshes {{ON_CLUSTER}}
TO user_last_seen_current AS
SELECT
    user_id,
    occurred_at AS last_seen,
    ip_addr,
    user_agent,
    occurred_at AS version
FROM user_auth_refreshes;

-- Materialized view: automatically populate user_last_seen_current from login events
CREATE MATERIALIZED VIEW IF NOT EXISTS mv_user_last_seen_from_logins {{ON_CLUSTER}}
TO user_last_seen_current AS
SELECT
    user_id,
    occurred_at AS last_seen,
    ip_addr,
    user_agent,
    occurred_at AS version
FROM user_auth_logins;
