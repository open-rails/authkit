-- Owner-namespace queries.
--
-- Permission groups own group-scoped routing now. The reserved-account guard is
-- users.metadata->>'reserved' (UserIsReserved); rename history is not authority.

-- name: UserIsReserved :one
SELECT (CASE
  WHEN jsonb_typeof(COALESCE(metadata, '{}'::jsonb)->'reserved')='boolean'
  THEN (COALESCE(metadata, '{}'::jsonb)->>'reserved')::boolean
  ELSE false
END)::boolean AS reserved
FROM users
WHERE id = sqlc.arg(id)::uuid;
