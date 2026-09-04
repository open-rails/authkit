-- A consumed refresh token remains attributable until its session is removed.
-- The session owns the family/user/issuer identity; do not duplicate that binding
-- in history. Cleanup of revoked/expired sessions cascades to their history.
CREATE TABLE profiles.refresh_token_history (
    token_hash bytea PRIMARY KEY,
    session_id uuid NOT NULL REFERENCES profiles.refresh_sessions(id) ON DELETE CASCADE,
    consumed_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX refresh_token_history_session_idx
    ON profiles.refresh_token_history (session_id);

-- Pre-launch hard cut: earlier rotations discarded hashes, which cannot be
-- reconstructed. Re-authentication creates a family with complete history.
UPDATE profiles.refresh_sessions SET revoked_at = now() WHERE revoked_at IS NULL;
ALTER TABLE profiles.refresh_sessions DROP COLUMN previous_token_hash;

COMMENT ON COLUMN profiles.refresh_sessions.previous_rotated_at IS
  'When the most recent predecessor rotated. Bounds the rotation grace window.';
