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
SELECT id::text, user_id, family_id::text, auth_methods
FROM profiles.refresh_sessions
WHERE current_token_hash = $1 AND issuer = $2 AND revoked_at IS NULL
  AND (expires_at IS NULL OR expires_at > now());

-- name: SessionByHistoricalTokenHash :one
-- A hash that was once current for a still-live family (ak#285). Feeds both
-- halves of the demoted-token decision: the ak#274 grace path (sealed successor,
-- the current hash it must open to, when it was sealed) and reuse detection (the
-- family to revoke).
SELECT s.id::text AS id, s.user_id, s.family_id::text AS family_id, s.auth_methods, s.expires_at,
       s.current_token_hash, s.previous_successor_sealed, s.previous_rotated_at
FROM profiles.refresh_token_history h
JOIN profiles.refresh_sessions s ON s.family_id = h.family_id
WHERE h.token_hash = $1 AND s.issuer = $2 AND s.revoked_at IS NULL;

-- name: SessionRotate :execrows
-- Compare-and-swap rotation conditioned on the hash the caller read. 0 rows means
-- a concurrent refresh already rotated this session (a lost race, NOT reuse) or it
-- was revoked. The demoted hash is recorded in refresh_token_history in the same
-- statement so it is never briefly unknown (ak#285); previous_successor_sealed /
-- previous_rotated_at let the ak#274 grace window re-deliver the successor.
WITH rotated AS (
  UPDATE profiles.refresh_sessions
  SET current_token_hash = sqlc.arg(new_token_hash), last_used_at = now(),
      user_agent = sqlc.arg(user_agent), ip_addr = sqlc.arg(ip_addr),
      previous_successor_sealed = sqlc.arg(previous_successor_sealed), previous_rotated_at = now()
  WHERE id = sqlc.arg(id) AND current_token_hash = sqlc.arg(expected_current_token_hash) AND revoked_at IS NULL
  RETURNING family_id
)
INSERT INTO profiles.refresh_token_history (token_hash, family_id)
SELECT sqlc.arg(expected_current_token_hash)::bytea, family_id FROM rotated;

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
       auth_methods
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
      SELECT DISTINCT unnest(auth_methods || sqlc.arg(auth_methods)::text[])
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

-- name: RefreshTokenHistoryDeleteOrphaned :exec
-- History lives exactly as long as a live family could still present it (ak#285).
DELETE FROM profiles.refresh_token_history h
WHERE NOT EXISTS (
  SELECT 1 FROM profiles.refresh_sessions s
  WHERE s.family_id = h.family_id AND s.revoked_at IS NULL
    AND (s.expires_at IS NULL OR s.expires_at > now())
);
