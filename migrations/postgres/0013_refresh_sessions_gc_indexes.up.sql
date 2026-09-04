-- #325: the session GC sweep deletes in bounded batches; these partial indexes
-- back the batch subquery so it never sequential-scans refresh_sessions.
CREATE INDEX IF NOT EXISTS refresh_sessions_dead_idx
  ON profiles.refresh_sessions (id)
  WHERE revoked_at IS NOT NULL;
CREATE INDEX IF NOT EXISTS refresh_sessions_expires_idx
  ON profiles.refresh_sessions (expires_at)
  WHERE revoked_at IS NULL AND expires_at IS NOT NULL;
