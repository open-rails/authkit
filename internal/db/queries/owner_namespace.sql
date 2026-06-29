-- Owner-namespace queries (core/service_owner_namespace*.go, core/owner_namespace_lookup.go).
--
-- Permission groups own group-scoped routing now. Only the user/owner-reserved
-- name namespace queries remain here.

-- name: OwnerReservedNameExists :one
SELECT EXISTS(
  SELECT 1 FROM profiles.owner_reserved_names WHERE slug = $1
);

-- name: OwnerReservedNameUpsert :exec
INSERT INTO profiles.owner_reserved_names (slug)
VALUES ($1)
ON CONFLICT (slug) DO UPDATE SET updated_at = now();

-- name: OwnerReservedNameDelete :execrows
DELETE FROM profiles.owner_reserved_names WHERE slug = $1;

-- name: UserIsReserved :one
SELECT (CASE
  WHEN jsonb_typeof(COALESCE(metadata, '{}'::jsonb)->'reserved')='boolean'
  THEN (COALESCE(metadata, '{}'::jsonb)->>'reserved')::boolean
  ELSE false
END)::boolean AS reserved
FROM profiles.users
WHERE id = sqlc.arg(id)::uuid;

-- name: UserSlugAliases :many
SELECT DISTINCT from_slug
FROM profiles.user_renames
WHERE user_id = sqlc.arg(user_id)::uuid
ORDER BY from_slug ASC;

-- name: UserBySlug :one
SELECT id::text, username::text
FROM profiles.users
WHERE username = $1 AND deleted_at IS NULL;
