-- Refresh-session queries (core/service_sessions.go).

-- name: SessionCreateLock :exec
-- Transaction-scoped advisory lock that serializes concurrent session creation for
-- the same (user, issuer). Taken before the cap count + evict + insert so those run
-- on a consistent view and the active session count can never exceed
-- SessionMaxPerUser under concurrent logins. Auto-released at transaction end; MUST
-- be called inside a transaction.
SELECT pg_advisory_xact_lock(hashtextextended(sqlc.arg(key)::text, 0));

-- name: SessionInsert :one
INSERT INTO profiles.refresh_sessions (id, family_id, user_id, issuer, current_token_hash, expires_at, user_agent, ip_addr, last_authenticated_at, auth_methods)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, now(), $9)
RETURNING id::text, family_id::text;

-- name: SessionByCurrentTokenHash :one
SELECT id::text, user_id, family_id::text,
       COALESCE(auth_methods, ARRAY['pwd']::text[])::text[] AS auth_methods
FROM profiles.refresh_sessions
WHERE current_token_hash = $1 AND issuer = $2 AND revoked_at IS NULL
  AND (expires_at IS NULL OR expires_at > now());

-- name: SessionByPreviousTokenHash :one
SELECT id::text, user_id, family_id::text
FROM profiles.refresh_sessions
WHERE previous_token_hash = $1 AND issuer = $2 AND revoked_at IS NULL;

-- name: SessionRotate :execrows
-- Conditional compare-and-swap: rotate only if the current hash still matches the
-- one the caller read. 0 rows affected means another concurrent refresh already
-- rotated this session (or it was revoked) — the caller must treat that as a lost
-- race, NOT as token reuse. This keeps reuse detection (previous_token_hash) sound.
UPDATE profiles.refresh_sessions
SET previous_token_hash = current_token_hash, current_token_hash = sqlc.arg(new_token_hash), last_used_at = now(), user_agent = sqlc.arg(user_agent), ip_addr = sqlc.arg(ip_addr)
WHERE id = sqlc.arg(id) AND current_token_hash = sqlc.arg(expected_current_token_hash) AND revoked_at IS NULL;

-- name: SessionsListByUser :many
-- last_authenticated_at and revoked_at are intentionally NOT selected: the
-- session-list handler never renders them, and revoked_at is always NULL here
-- (the WHERE clause filters to non-revoked rows), so reading them was pure
-- over-fetch (#230).
SELECT id::text, family_id::text, created_at, last_used_at, expires_at,
       user_agent, CASE WHEN ip_addr IS NULL THEN NULL ELSE NULLIF(host(ip_addr)::text, '') END AS ip_addr
FROM profiles.refresh_sessions
WHERE user_id = $1 AND issuer = $2 AND (revoked_at IS NULL);

-- name: SessionFreshSince :one
SELECT COALESCE(last_authenticated_at, created_at)::timestamptz AS fresh_since,
       COALESCE(auth_methods, ARRAY['pwd']::text[])::text[] AS auth_methods
FROM profiles.refresh_sessions
WHERE id = sqlc.arg(session_id)::uuid
  AND user_id = sqlc.arg(user_id)::uuid
  AND issuer = $3
  AND revoked_at IS NULL
  AND (expires_at IS NULL OR expires_at > now());

-- name: SessionMarkAuthenticated :execrows
-- Re-proving identity refreshes the freshness window and UNIONS the methods
-- just used into whatever the session already proved — it never downgrades
-- assurance. A password-only re-auth on an MFA session keeps its otp/mfa AMR,
-- so a later RequireMFA gate still passes.
UPDATE profiles.refresh_sessions
SET last_authenticated_at = now(),
    auth_methods = ARRAY(
      SELECT DISTINCT unnest(COALESCE(auth_methods, '{}'::text[]) || sqlc.arg(auth_methods)::text[])
    )
WHERE id = sqlc.arg(session_id)::uuid
  AND user_id = sqlc.arg(user_id)::uuid
  AND issuer = sqlc.arg(issuer)
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
