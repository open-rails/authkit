-- name: ResolveUsername :one
SELECT u.id::text AS id, u.username::text AS canonical_name, COALESCE(NOT c.canonical,false)::boolean AS is_alias, c.expires_at
FROM name_claims c JOIN users u ON u.id=c.owner_id
WHERE c.owner_kind='user' AND c.persona='' AND c.name=lower(sqlc.arg(name)::text)
 AND (c.canonical OR c.expires_at IS NULL OR c.expires_at>sqlc.arg(at_time)::timestamptz)
 AND u.deleted_at IS NULL;

-- name: NameClaimsDeleteExpired :execrows
WITH expired AS (
 SELECT owner_kind,persona,name FROM name_claims
 WHERE NOT canonical AND expires_at <= sqlc.arg(at_time)::timestamptz
 ORDER BY expires_at LIMIT 5000 FOR UPDATE SKIP LOCKED
)
DELETE FROM name_claims c USING expired e
WHERE c.owner_kind=e.owner_kind AND c.persona=e.persona AND c.name=e.name
 AND NOT c.canonical AND c.expires_at <= sqlc.arg(at_time)::timestamptz;

-- name: NameClaimsLock :exec
-- Takes the names' stripe locks in stripe order, so opposite renames cannot deadlock.
SELECT lock_name_claims('user', '', sqlc.arg(names)::text[]);

-- name: NameClaimCanonical :exec
SELECT claim_canonical_name('user', '', sqlc.arg(name)::text, sqlc.arg(owner_id)::uuid, sqlc.arg(at_time)::timestamptz);

-- name: NameClaimDeleteOwned :exec
DELETE FROM name_claims
WHERE owner_kind = 'user' AND persona = '' AND name = lower(sqlc.arg(name)::text) AND owner_id = sqlc.arg(owner_id) AND canonical;

-- name: NameClaimRetire :exec
-- The canonical name becomes an alias until expires_at (NULL: kept for good).
UPDATE name_claims SET canonical = false, expires_at = sqlc.narg(expires_at)
WHERE owner_kind = 'user' AND persona = '' AND name = lower(sqlc.arg(name)::text) AND owner_id = sqlc.arg(owner_id) AND canonical;

-- name: NameClaimTaken :one
SELECT EXISTS(SELECT 1 FROM name_claims WHERE owner_kind = 'user' AND persona = '' AND name = lower(sqlc.arg(name)::text)
  AND (canonical OR expires_at IS NULL OR expires_at > sqlc.arg(at_time)::timestamptz));

-- name: UserLastRenamedAt :one
SELECT last_renamed_at FROM users WHERE id = $1 AND deleted_at IS NULL;

-- name: NameClaimAliasesByUser :many
SELECT name, expires_at FROM name_claims
WHERE owner_kind = 'user' AND owner_id = sqlc.arg(owner_id) AND NOT canonical
  AND (expires_at IS NULL OR expires_at > sqlc.arg(at_time)::timestamptz)
ORDER BY name;
