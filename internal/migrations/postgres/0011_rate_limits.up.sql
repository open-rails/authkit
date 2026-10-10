-- parent: 10 sha256:40cc13373e7437ee107e8d26d7d15fde4c391a322a51f23c7dd1a237c802795c
-- Rate-limit budgets (HTTPConfig.RateLimits) every replica spends: one row per
-- bucket and client key, holding the times, in Unix milliseconds on the
-- database clock, of the requests admitted within the bucket's window, oldest
-- first. While Deps.Redis answers, the budgets are spent there instead. A row
-- is dead from expires_at, when its newest request leaves the window, and is
-- deleted by the maintenance job.
SET LOCAL lock_timeout = '10s';

CREATE TABLE rate_limits (
  key text PRIMARY KEY,
  hits bigint[] NOT NULL,
  expires_at timestamptz NOT NULL
);
COMMENT ON TABLE rate_limits IS 'Sliding-window rate-limit budgets shared by every replica; rows past expires_at are deleted.';
CREATE INDEX rate_limits_expires_at_idx ON rate_limits (expires_at);
