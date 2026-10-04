-- parent: 7 sha256:36b020e819f99dbc1613a8a3f414474c61c54335c930340ba188d5a84bfe7dc7
-- An account's ban history: every ban put in force and every ban lifted, with
-- who did it. users keeps only the ban in force.
SET LOCAL lock_timeout = '10s';

CREATE TABLE user_ban_events (
  id uuid PRIMARY KEY DEFAULT uuidv7(),
  user_id uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  kind text NOT NULL,
  occurred_at timestamptz NOT NULL,
  banned_until timestamptz,
  reason text,
  actor_id uuid REFERENCES users(id) ON DELETE SET NULL,
  CONSTRAINT user_ban_events_kind_chk CHECK (kind IN ('banned', 'unbanned'))
);
CREATE INDEX user_ban_events_user_idx
  ON user_ban_events (user_id, occurred_at DESC, id DESC);
CREATE INDEX user_ban_events_actor_idx
  ON user_ban_events (actor_id)
  WHERE actor_id IS NOT NULL;
COMMENT ON TABLE user_ban_events IS
  'Ban history: one row per ban put in force (banned) or lifted (unbanned). actor_id NULL = the system.';

-- The bans on record start the history.
INSERT INTO user_ban_events (user_id, kind, occurred_at, banned_until, reason, actor_id)
SELECT id, 'banned', banned_at, banned_until, ban_reason, banned_by
FROM users WHERE banned_at IS NOT NULL;
