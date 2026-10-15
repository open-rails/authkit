-- name: IdentityPublicUsersByIDs :many
-- The PUBLIC-safe display projection (#268): no email column is selected, so a
-- caller cannot leak one by forgetting a tag. Soft-deleted rows ARE returned —
-- the Go layer tombstones them — so a reference to a deleted author resolves to
-- a stable placeholder instead of silently vanishing.
SELECT id, username, created_at, deleted_at, public_metadata
FROM users
WHERE tenant_id=NULLIF(sqlc.arg(tenant_id)::text,'')::uuid AND id = ANY(sqlc.arg(ids)::uuid[]);
