-- Owner-namespace queries (core/service_owner_namespace*.go, core/owner_namespace_lookup.go).
--
-- Permission groups own group-scoped routing now. The reserved-account guard is
-- users.metadata->>'reserved' (UserIsReserved); active aliases come from name_claims; rename history is not authority.

-- name: UserIsReserved :one
SELECT (CASE
  WHEN jsonb_typeof(COALESCE(metadata, '{}'::jsonb)->'reserved')='boolean'
  THEN (COALESCE(metadata, '{}'::jsonb)->>'reserved')::boolean
  ELSE false
END)::boolean AS reserved
FROM profiles.users
WHERE id = sqlc.arg(id)::uuid;

-- name: UserSlugAliases :many
SELECT c.name AS from_slug
FROM profiles.name_claims c JOIN profiles.users u ON u.id=c.owner_id
WHERE c.owner_kind='user' AND c.owner_id=sqlc.arg(user_id)::uuid AND NOT c.canonical
  AND (c.expires_at IS NULL OR c.expires_at > sqlc.arg(at_time)::timestamptz)
  AND u.deleted_at IS NULL
ORDER BY c.name ASC;
