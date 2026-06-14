-- Reserved-account + metadata queries (core/service_reserved_accounts.go).

-- name: UserSetReserved :exec
UPDATE profiles.users
SET metadata = jsonb_set(COALESCE(metadata, '{}'::jsonb), '{reserved}', to_jsonb(sqlc.arg(reserved)::boolean), true),
    updated_at = now()
WHERE id = sqlc.arg(id)::uuid;

-- name: OrgSetReserved :exec
UPDATE profiles.orgs
SET metadata = jsonb_set(COALESCE(metadata, '{}'::jsonb), '{reserved}', to_jsonb(sqlc.arg(reserved)::boolean), true),
    updated_at = now()
WHERE id = sqlc.arg(id)::uuid;

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

-- name: OrgMetadata :one
SELECT COALESCE(metadata, '{}'::jsonb)::jsonb AS metadata
FROM profiles.orgs WHERE id = sqlc.arg(id)::uuid AND deleted_at IS NULL;

-- name: OrgMetadataPatch :execrows
UPDATE profiles.orgs
SET metadata = COALESCE(metadata, '{}'::jsonb) || sqlc.arg(patch)::jsonb,
    updated_at = now()
WHERE id = sqlc.arg(id)::uuid AND deleted_at IS NULL;

-- name: OrgIDReservedBySlug :one
SELECT id::text,
       (CASE
         WHEN jsonb_typeof(COALESCE(metadata, '{}'::jsonb)->'reserved')='boolean'
         THEN (COALESCE(metadata, '{}'::jsonb)->>'reserved')::boolean
         ELSE false
       END)::boolean AS reserved
FROM profiles.orgs
WHERE slug = $1
  AND deleted_at IS NULL;

-- name: UserIDReservedByUsername :one
SELECT id::text,
       (CASE
         WHEN jsonb_typeof(COALESCE(metadata, '{}'::jsonb)->'reserved')='boolean'
         THEN (COALESCE(metadata, '{}'::jsonb)->>'reserved')::boolean
         ELSE false
       END)::boolean AS reserved
FROM profiles.users
WHERE username = $1
  AND deleted_at IS NULL;

-- name: PersonalOrgIDSlugReservedByOwner :one
SELECT id::text,
       slug,
       (CASE
         WHEN jsonb_typeof(COALESCE(metadata, '{}'::jsonb)->'reserved')='boolean'
         THEN (COALESCE(metadata, '{}'::jsonb)->>'reserved')::boolean
         ELSE false
       END)::boolean AS reserved
FROM profiles.orgs
WHERE owner_user_id = sqlc.arg(owner_user_id)::uuid
  AND is_personal = true
  AND deleted_at IS NULL;
