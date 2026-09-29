-- Reserved-account + metadata queries.

-- name: UserMetadata :one
SELECT COALESCE(metadata, '{}'::jsonb)::jsonb AS metadata
FROM users WHERE id = sqlc.arg(id)::uuid;
