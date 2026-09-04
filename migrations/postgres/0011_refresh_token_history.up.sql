-- ak#285: refresh-token reuse detection across the whole family.
--
-- A session row kept exactly one demoted hash, so a token two rotations old was
-- "unknown" rather than "reused": an attacker who rotated a stolen token twice
-- silently evicted the victim and kept the live credential, and the family
-- revoke never fired. Every demoted hash now lands in refresh_token_history for
-- as long as its family is live. A presented hash found there is reuse — and
-- revokes the family — unless it is the sealed grace predecessor of the current
-- token inside the ak#274 window, which is decided by opening the seal, not by
-- a stored hash. Rows are pruned with their family by CleanupExpiredAuthState.
CREATE TABLE IF NOT EXISTS profiles.refresh_token_history (
  token_hash bytea PRIMARY KEY,
  family_id uuid NOT NULL,
  demoted_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS refresh_token_history_family
  ON profiles.refresh_token_history (family_id);

INSERT INTO profiles.refresh_token_history (token_hash, family_id, demoted_at)
SELECT previous_token_hash, family_id, COALESCE(previous_rotated_at, now())
FROM profiles.refresh_sessions
WHERE previous_token_hash IS NOT NULL AND revoked_at IS NULL
ON CONFLICT DO NOTHING;

DROP INDEX IF EXISTS profiles.refresh_sessions_prev_hash_active;
ALTER TABLE profiles.refresh_sessions DROP COLUMN previous_token_hash;

COMMENT ON COLUMN profiles.refresh_sessions.previous_rotated_at IS
  'When the last rotation demoted its predecessor. Bounds the rotation grace window (ak#274).';
