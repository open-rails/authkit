-- API key queries (core/api_keys.go).
--
-- An API key holds exactly ONE org role (#95). Its effective permissions are
-- resolved FROM that role (profiles.org_role_permissions) at use time, so the
-- queries here only ever carry the role NAME — never a per-key permission list.
-- There is no service_token_permissions table.

-- name: APIKeyInsert :one
INSERT INTO profiles.service_tokens
  (org_id, key_id, secret_hash, name, role, created_by, expires_at)
VALUES (sqlc.arg(org_id)::uuid, $2, $3, $4, $5, sqlc.narg(created_by)::uuid, $7)
RETURNING id::text, created_at;

-- name: APIKeyResourceInsert :exec
INSERT INTO profiles.service_token_resources (token_id, kind, resource_id)
VALUES (sqlc.arg(api_key_id)::uuid, $2, $3);

-- name: APIKeysByOrg :many
SELECT id::text, key_id, name, role,
       COALESCE(created_by::text, '')::text AS created_by,
       created_at, last_used_at, expires_at, revoked_at
FROM profiles.service_tokens
WHERE org_id = sqlc.arg(org_id)::uuid
ORDER BY created_at DESC;

-- name: APIKeyRevoke :execrows
UPDATE profiles.service_tokens
SET revoked_at = now()
WHERE id = sqlc.arg(id)::uuid AND org_id = sqlc.arg(org_id)::uuid AND revoked_at IS NULL;

-- name: APIKeyByKeyID :one
SELECT t.id::text AS id, t.secret_hash, t.role, t.expires_at, t.revoked_at,
       o.id::text AS org_id, o.slug, o.deleted_at AS org_deleted_at
FROM profiles.service_tokens t
JOIN profiles.orgs o ON o.id = t.org_id
WHERE t.key_id = $1;

-- name: APIKeyTouchLastUsed :exec
UPDATE profiles.service_tokens SET last_used_at = now() WHERE id = sqlc.arg(id)::uuid;

-- name: APIKeyResourcesByAPIKeyIDs :many
SELECT token_id::text AS api_key_id, kind, resource_id
FROM profiles.service_token_resources
WHERE token_id = ANY(sqlc.arg(ids)::uuid[])
ORDER BY token_id::text, kind, resource_id;

-- name: APIKeyResourcesByAPIKeyID :many
SELECT kind, resource_id
FROM profiles.service_token_resources
WHERE token_id = sqlc.arg(api_key_id)::uuid
ORDER BY kind, resource_id;
