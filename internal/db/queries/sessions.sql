-- Refresh-session queries (core/service_sessions.go).

-- name: SessionInsert :one
INSERT INTO profiles.refresh_sessions (id, family_id, user_id, issuer, current_token_hash, expires_at, user_agent, ip_addr, last_authenticated_at)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, now())
RETURNING id::text, family_id::text;

-- name: SessionByCurrentTokenHash :one
SELECT id::text, user_id, family_id::text
FROM profiles.refresh_sessions
WHERE current_token_hash = $1 AND issuer = $2 AND revoked_at IS NULL
  AND (expires_at IS NULL OR expires_at > now());

-- name: SessionByPreviousTokenHash :one
SELECT id::text, user_id, family_id::text
FROM profiles.refresh_sessions
WHERE previous_token_hash = $1 AND issuer = $2 AND revoked_at IS NULL;

-- name: SessionRotate :exec
UPDATE profiles.refresh_sessions
SET previous_token_hash = current_token_hash, current_token_hash = $1, last_used_at = now(), user_agent = $2, ip_addr = $3
WHERE id = $4 AND revoked_at IS NULL;

-- name: SessionsListByUser :many
SELECT id::text, family_id::text, created_at, last_authenticated_at, last_used_at, expires_at, revoked_at,
       user_agent, CASE WHEN ip_addr IS NULL THEN NULL ELSE NULLIF(host(ip_addr)::text, '') END AS ip_addr
FROM profiles.refresh_sessions
WHERE user_id = $1 AND issuer = $2 AND (revoked_at IS NULL);

-- name: SessionFreshSince :one
SELECT COALESCE(last_authenticated_at, created_at)::timestamptz AS fresh_since
FROM profiles.refresh_sessions
WHERE id = sqlc.arg(session_id)::uuid
  AND user_id = sqlc.arg(user_id)::uuid
  AND issuer = $3
  AND revoked_at IS NULL
  AND (expires_at IS NULL OR expires_at > now());

-- name: SessionMarkAuthenticated :execrows
UPDATE profiles.refresh_sessions
SET last_authenticated_at = now()
WHERE id = sqlc.arg(session_id)::uuid
  AND user_id = sqlc.arg(user_id)::uuid
  AND issuer = $3
  AND revoked_at IS NULL
  AND (expires_at IS NULL OR expires_at > now());

-- name: SessionIDByCurrentTokenHash :one
SELECT id::text
FROM profiles.refresh_sessions
WHERE current_token_hash = $1 AND issuer = $2 AND revoked_at IS NULL
  AND (expires_at IS NULL OR expires_at > now());

-- name: SessionRevokeByID :one
UPDATE profiles.refresh_sessions SET revoked_at = now()
WHERE id = $1 AND issuer = $2 AND revoked_at IS NULL
RETURNING user_id::text;

-- name: SessionRevokeByIDForUser :one
UPDATE profiles.refresh_sessions SET revoked_at = now()
WHERE id = $1 AND user_id = $2 AND issuer = $3 AND revoked_at IS NULL
RETURNING id::text;

-- name: SessionsRevokeAllExcept :many
UPDATE profiles.refresh_sessions SET revoked_at = now()
WHERE user_id = $1 AND issuer = $2 AND id <> $3 AND revoked_at IS NULL
RETURNING id::text;

-- name: SessionsRevokeAll :many
UPDATE profiles.refresh_sessions SET revoked_at = now()
WHERE user_id = $1 AND issuer = $2 AND revoked_at IS NULL
RETURNING id::text;

-- name: SessionsCountActive :one
SELECT count(*) FROM profiles.refresh_sessions
WHERE user_id = $1 AND issuer = $2 AND revoked_at IS NULL
  AND (expires_at IS NULL OR expires_at > now());

-- name: SessionsEvictOldest :many
UPDATE profiles.refresh_sessions SET revoked_at = now()
WHERE id IN (
  SELECT id FROM profiles.refresh_sessions
  WHERE user_id = sqlc.arg(user_id)::uuid AND issuer = sqlc.arg(issuer)::text AND revoked_at IS NULL
    AND (expires_at IS NULL OR expires_at > now())
  ORDER BY last_used_at ASC
  LIMIT sqlc.arg(evict_count)::bigint
)
RETURNING id::text;

-- name: SessionsRevokeFamily :many
UPDATE profiles.refresh_sessions SET revoked_at = now()
WHERE family_id = $1 AND revoked_at IS NULL
RETURNING id::text, user_id::text;

-- name: SessionsDeleteRevokedOrExpired :exec
DELETE FROM profiles.refresh_sessions
WHERE revoked_at IS NOT NULL
   OR (expires_at IS NOT NULL AND expires_at <= NOW());
