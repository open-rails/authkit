-- Service token queries (core/service_tokens.go).

-- name: ServiceTokenInsert :one
INSERT INTO profiles.service_tokens
  (tenant_id, key_id, secret_hash, name, created_by, expires_at)
VALUES (sqlc.arg(tenant_id)::uuid, $2, $3, $4, sqlc.narg(created_by)::uuid, $6)
RETURNING id::text, created_at;

-- name: ServiceTokenPermissionInsert :exec
INSERT INTO profiles.service_token_permissions (service_token_id, permission)
VALUES (sqlc.arg(service_token_id)::uuid, $2);

-- name: ServiceTokenResourceInsert :exec
INSERT INTO profiles.service_token_resources (token_id, kind, resource_id)
VALUES (sqlc.arg(token_id)::uuid, $2, $3);

-- name: ServiceTokensByTenant :many
SELECT id::text, key_id, name, COALESCE(created_by::text, '')::text AS created_by,
       created_at, last_used_at, expires_at, revoked_at
FROM profiles.service_tokens
WHERE tenant_id = sqlc.arg(tenant_id)::uuid
ORDER BY created_at DESC;

-- name: ServiceTokenRevoke :execrows
UPDATE profiles.service_tokens
SET revoked_at = now()
WHERE id = sqlc.arg(id)::uuid AND tenant_id = sqlc.arg(tenant_id)::uuid AND revoked_at IS NULL;

-- name: ServiceTokenByKeyID :one
SELECT t.id::text AS id, t.secret_hash, t.expires_at, t.revoked_at,
       o.slug, o.deleted_at AS tenant_deleted_at
FROM profiles.service_tokens t
JOIN profiles.tenants o ON o.id = t.tenant_id
WHERE t.key_id = $1;

-- name: ServiceTokenTouchLastUsed :exec
UPDATE profiles.service_tokens SET last_used_at = now() WHERE id = sqlc.arg(id)::uuid;

-- name: ServiceTokenPermissionsByTokenIDs :many
SELECT service_token_id::text AS service_token_id, permission
FROM profiles.service_token_permissions
WHERE service_token_id = ANY(sqlc.arg(ids)::uuid[])
ORDER BY service_token_id::text, permission;

-- name: ServiceTokenPermissionsByTokenID :many
SELECT permission
FROM profiles.service_token_permissions
WHERE service_token_id = sqlc.arg(service_token_id)::uuid
ORDER BY permission;

-- name: ServiceTokenResourcesByTokenIDs :many
SELECT token_id::text AS token_id, kind, resource_id
FROM profiles.service_token_resources
WHERE token_id = ANY(sqlc.arg(ids)::uuid[])
ORDER BY token_id::text, kind, resource_id;

-- name: ServiceTokenResourcesByTokenID :many
SELECT kind, resource_id
FROM profiles.service_token_resources
WHERE token_id = sqlc.arg(token_id)::uuid
ORDER BY kind, resource_id;
