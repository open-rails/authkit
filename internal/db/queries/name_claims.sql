-- name: ResolveUsername :one
SELECT u.id::text AS id, u.username::text AS canonical_name, COALESCE(NOT c.canonical,false)::boolean AS is_alias, c.expires_at
FROM profiles.name_claims c JOIN profiles.users u ON u.id=c.owner_id
WHERE c.owner_kind='user' AND c.persona='' AND c.name=lower(sqlc.arg(name)::text)
 AND (c.canonical OR c.expires_at IS NULL OR c.expires_at>sqlc.arg(at_time)::timestamptz)
 AND u.deleted_at IS NULL;

-- name: NameClaimsDeleteExpired :execrows
WITH expired AS (
 SELECT owner_kind,persona,name FROM profiles.name_claims
 WHERE NOT canonical AND expires_at <= sqlc.arg(at_time)::timestamptz
 ORDER BY expires_at LIMIT 5000 FOR UPDATE SKIP LOCKED
)
DELETE FROM profiles.name_claims c USING expired e
WHERE c.owner_kind=e.owner_kind AND c.persona=e.persona AND c.name=e.name
 AND NOT c.canonical AND c.expires_at <= sqlc.arg(at_time)::timestamptz;
