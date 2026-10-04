-- Ban history: one user_ban_events row per ban put in force or lifted,
-- written in the transaction of the change.

-- name: BanEventInsert :exec
INSERT INTO user_ban_events (user_id, kind, occurred_at, banned_until, reason, actor_id)
VALUES (sqlc.arg(user_id)::uuid, sqlc.arg(kind), sqlc.arg(occurred_at), sqlc.narg(banned_until), sqlc.narg(reason), sqlc.narg(actor_id)::uuid);

-- name: BanEventsRecordCreated :exec
-- The ban each of the new accounts was created with, if any.
INSERT INTO user_ban_events (user_id, kind, occurred_at, banned_until, reason, actor_id)
SELECT id, 'banned', banned_at, banned_until, ban_reason, banned_by
FROM users WHERE id = ANY(sqlc.arg(user_ids)::uuid[]) AND banned_at IS NOT NULL;

-- name: BanEventsByUser :many
-- One page of an account's ban history, newest first, after the (after_at,
-- after_id) keyset cursor when after_at is set.
SELECT * FROM user_ban_events
WHERE user_id = sqlc.arg(user_id)::uuid
  AND (sqlc.narg(after_at)::timestamptz IS NULL
       OR (occurred_at, id) < (sqlc.narg(after_at)::timestamptz, sqlc.narg(after_id)::uuid))
ORDER BY occurred_at DESC, id DESC
LIMIT sqlc.arg(page_limit)::bigint;
