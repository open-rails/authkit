-- Reserved-account + metadata queries (core/service_reserved_accounts.go).

-- name: UserMetadata :one
SELECT COALESCE(metadata, '{}'::jsonb)::jsonb AS metadata
FROM profiles.users WHERE id = sqlc.arg(id)::uuid;

-- name: UserMetadataPatch :execrows
UPDATE profiles.users
SET metadata = COALESCE(metadata, '{}'::jsonb) || sqlc.arg(patch)::jsonb,
    updated_at = now()
WHERE id = sqlc.arg(id)::uuid;
