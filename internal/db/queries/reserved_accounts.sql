-- Reserved-account + metadata queries (core/service_reserved_accounts.go).

-- name: UserPasswordDelete :exec
DELETE FROM profiles.user_passwords WHERE user_id = sqlc.arg(user_id)::uuid;

-- name: UserProvidersDeleteByUser :exec
DELETE FROM profiles.user_providers WHERE user_id = sqlc.arg(user_id)::uuid;

-- name: UserClearLoginIdentifiers :exec
UPDATE profiles.users
SET email = NULL,
    email_verified = false,
    phone_number = NULL,
    phone_verified = false,
    updated_at = now()
WHERE id = sqlc.arg(id)::uuid;

-- name: UserMetadata :one
SELECT COALESCE(metadata, '{}'::jsonb)::jsonb AS metadata
FROM profiles.users WHERE id = sqlc.arg(id)::uuid;

-- name: UserMetadataPatch :execrows
UPDATE profiles.users
SET metadata = COALESCE(metadata, '{}'::jsonb) || sqlc.arg(patch)::jsonb,
    updated_at = now()
WHERE id = sqlc.arg(id)::uuid;
