-- name: ResolveUsername :one
SELECT u.id::text AS id, u.username::text AS canonical_name, COALESCE(NOT c.canonical,false)::boolean AS is_alias, c.expires_at
FROM profiles.name_claims c JOIN profiles.users u ON u.id=c.owner_id
WHERE c.owner_kind='user' AND c.persona='' AND c.name=lower(sqlc.arg(name)::text)
 AND (c.canonical OR c.expires_at IS NULL OR c.expires_at>sqlc.arg(at_time)::timestamptz)
 AND u.deleted_at IS NULL;
