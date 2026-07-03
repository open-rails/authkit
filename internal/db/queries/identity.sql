-- Batch user projections (core user enrichment paths).

-- name: IdentityUsersByIDs :many
SELECT id, username, email
FROM profiles.users
WHERE id = ANY(sqlc.arg(ids)::uuid[]);
