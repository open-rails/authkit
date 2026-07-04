-- Session-event history (sign-ins, revocations, password changes), moved from
-- ClickHouse (#245). Append-only, best-effort; pruned by CleanupExpiredAuthState
-- per Config.SessionEventRetention. user_id is text with no FK: events outlive
-- hard-deleted users for forensics until retention prunes them.

CREATE TABLE IF NOT EXISTS profiles.session_events (
    id          bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    occurred_at timestamptz NOT NULL,
    issuer      text NOT NULL,
    user_id     text NOT NULL,
    session_id  text NOT NULL,
    event       text NOT NULL,
    method      text,
    reason      text,
    ip_addr     text,
    user_agent  text
);

-- Reader: per-user history newest-first (also serves last-login lookups).
CREATE INDEX IF NOT EXISTS session_events_user_occurred_idx
    ON profiles.session_events (user_id, occurred_at DESC);

-- Pruner: retention sweep walks this index in bounded batches.
CREATE INDEX IF NOT EXISTS session_events_occurred_idx
    ON profiles.session_events (occurred_at);
