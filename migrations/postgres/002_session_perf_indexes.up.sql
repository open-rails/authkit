-- Session-query performance indexes (from the internal/db/querytest plan audit).
--
-- 1. SessionsRevokeFamily filtered by family_id with no supporting index and
--    sequentially scanned refresh_sessions on every token-reuse revocation.
--    Index the live-row lookup.
-- 2. SessionsEvictOldest orders by last_used_at, but the per-user active index
--    stopped at (user_id, issuer), forcing a Sort of all of a user's sessions.
--    Extend it to carry last_used_at so eviction is index-ordered and the LIMIT
--    short-circuits. The (user_id, issuer) prefix still serves the list/count
--    lookups.

CREATE INDEX IF NOT EXISTS refresh_sessions_family_active
  ON profiles.refresh_sessions (family_id)
  WHERE revoked_at IS NULL;

DROP INDEX IF EXISTS profiles.refresh_sessions_user_active;
CREATE INDEX IF NOT EXISTS refresh_sessions_user_active
  ON profiles.refresh_sessions (user_id, issuer, last_used_at)
  WHERE revoked_at IS NULL;
