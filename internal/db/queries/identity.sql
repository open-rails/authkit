-- Identity store queries (identity package).

-- name: IdentityUsersByIDs :many
SELECT id, username, email
FROM profiles.users
WHERE id = ANY(sqlc.arg(ids)::uuid[]);

-- name: IdentityUserByID :one
SELECT id, email, username, email_verified
FROM profiles.users
WHERE id = $1
LIMIT 1;

-- name: IdentityUpdateUserUsername :exec
UPDATE profiles.users SET username = $2, updated_at = now() WHERE id = $1;

-- Rename-history forwarding (identity/renames.go).

-- name: IdentityForwardUsername :one
SELECT u.username
FROM profiles.user_renames r
JOIN profiles.users u ON u.id = r.user_id AND u.deleted_at IS NULL
WHERE r.from_slug = $1
ORDER BY r.renamed_at DESC
LIMIT 1;
