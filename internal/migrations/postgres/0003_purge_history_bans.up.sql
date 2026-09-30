-- parent: 2 sha256:2537923d8db1b3fd706d48689cfd9c59c6899da983393804ae957ce928054ce2
-- Account and group purges find every referencing row through an index,
-- refresh-token history is kept 90 days, and a ban exists exactly while
-- banned_at is set.
SET LOCAL lock_timeout = '10s';

-- A purge deletes one row; Postgres then finds each row that references it
-- with `fk = $1`, which a partial index serves only when its predicate follows
-- from that.
CREATE INDEX users_banned_by_idx
  ON users (banned_by)
  WHERE banned_by IS NOT NULL;
DROP INDEX refresh_sessions_user_active;
CREATE INDEX refresh_sessions_user_idx
  ON refresh_sessions (user_id, issuer, last_used_at);
DROP INDEX idx_user_passkeys_user_active;
CREATE INDEX user_passkeys_user_idx
  ON user_passkeys (user_id);
DROP INDEX user_device_keys_user_active_idx;
CREATE INDEX user_device_keys_user_idx
  ON user_device_keys (user_id);
DROP INDEX group_invite_links_group_idx;
CREATE INDEX group_invite_links_group_idx
  ON group_invite_links (permission_group_id);
CREATE INDEX account_registration_invites_group_idx
  ON account_registration_invites (permission_group_id);
-- Written, never read.
ALTER TABLE account_registration_invites DROP COLUMN consumed_by;

-- Rotation prunes a session's history older than 90 days (SessionRotate);
-- this drops what is already older.
DELETE FROM refresh_token_history WHERE consumed_at < now() - interval '90 days';
DROP INDEX refresh_token_history_session_idx;
CREATE INDEX refresh_token_history_session_idx
  ON refresh_token_history (session_id, consumed_at);

-- A row a host wrote by hand with ban columns but no banned_at stays banned,
-- as the sign-in gate treated it, unless the ban has expired.
UPDATE users SET banned_at = updated_at
WHERE banned_at IS NULL AND num_nonnulls(banned_until, ban_reason, banned_by) > 0
  AND (banned_until IS NULL OR banned_until > statement_timestamp());
UPDATE users SET banned_until = NULL, ban_reason = NULL, banned_by = NULL
WHERE banned_at IS NULL AND num_nonnulls(banned_until, ban_reason, banned_by) > 0;
ALTER TABLE users ADD CONSTRAINT users_ban_chk
  CHECK (banned_at IS NOT NULL OR num_nulls(banned_until, ban_reason, banned_by) = 3);

-- The one test of a ban in force: an expired temporary ban is no ban. It
-- inlines, so the partial ban index still serves it.
CREATE FUNCTION ban_in_force(banned_at timestamptz, banned_until timestamptz) RETURNS boolean
LANGUAGE sql STABLE
RETURN banned_at IS NOT NULL AND (banned_until IS NULL OR banned_until > statement_timestamp());

CREATE OR REPLACE VIEW usable_users AS
SELECT id FROM users
WHERE deleted_at IS NULL
  AND COALESCE(metadata->'reserved', 'false'::jsonb) <> 'true'::jsonb
  AND NOT ban_in_force(banned_at, banned_until);
