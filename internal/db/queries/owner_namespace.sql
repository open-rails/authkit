-- Owner-namespace queries (core/service_owner_namespace*.go, core/owner_namespace_lookup.go).
--
-- Permission groups own group-scoped routing now. The reserved-account guard is
-- users.metadata->>'reserved' (UserIsReserved); slug aliases come from user_renames.

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
