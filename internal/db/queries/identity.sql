-- name: IdentityPublicUsersByIDs :many
-- The PUBLIC-safe display projection (#268): no email column is selected, so a
-- caller cannot leak one by forgetting a tag. Soft-deleted rows ARE returned —
-- the Go layer tombstones them — so a reference to a deleted author resolves to
-- a stable placeholder instead of silently vanishing.
SELECT id, username, avatar_url, created_at, deleted_at
FROM users
WHERE id = ANY(sqlc.arg(ids)::uuid[]);
