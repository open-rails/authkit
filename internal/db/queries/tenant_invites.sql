-- Tenant invite queries (core/service_tenant_invites.go).

-- name: TenantInviteInsert :one
INSERT INTO profiles.tenant_invites (id, tenant_id, user_id, invited_by, role, status, expires_at)
VALUES (sqlc.arg(id)::uuid, sqlc.arg(tenant_id)::uuid, sqlc.arg(user_id)::uuid, sqlc.arg(invited_by)::uuid, $5, 'pending', $6)
RETURNING id::text, user_id::text, invited_by::text, role, status, expires_at, acted_at, created_at;

-- name: TenantInvitesByTenant :many
SELECT id::text, user_id::text, invited_by::text, role, status, expires_at, acted_at, created_at
FROM profiles.tenant_invites
WHERE tenant_id = sqlc.arg(tenant_id)::uuid AND deleted_at IS NULL
ORDER BY created_at DESC;

-- name: TenantInvitesByTenantStatus :many
SELECT id::text, user_id::text, invited_by::text, role, status, expires_at, acted_at, created_at
FROM profiles.tenant_invites
WHERE tenant_id = sqlc.arg(tenant_id)::uuid AND status = $2 AND deleted_at IS NULL
ORDER BY created_at DESC;

-- name: TenantInvitesByUser :many
SELECT i.id::text AS id, o.slug, i.user_id::text AS user_id, i.invited_by::text AS invited_by, i.role, i.status, i.expires_at, i.acted_at, i.created_at
FROM profiles.tenant_invites i
JOIN profiles.tenants o ON o.id = i.tenant_id
WHERE i.user_id = sqlc.arg(user_id)::uuid AND i.deleted_at IS NULL AND o.deleted_at IS NULL
ORDER BY i.created_at DESC;

-- name: TenantInvitesByUserStatus :many
SELECT i.id::text AS id, o.slug, i.user_id::text AS user_id, i.invited_by::text AS invited_by, i.role, i.status, i.expires_at, i.acted_at, i.created_at
FROM profiles.tenant_invites i
JOIN profiles.tenants o ON o.id = i.tenant_id
WHERE i.user_id = sqlc.arg(user_id)::uuid AND i.status = $2 AND i.deleted_at IS NULL AND o.deleted_at IS NULL
ORDER BY i.created_at DESC;

-- name: TenantInviteRevoke :execrows
UPDATE profiles.tenant_invites
SET status = 'revoked', acted_at = now(), updated_at = now()
WHERE id = sqlc.arg(id)::uuid AND tenant_id = sqlc.arg(tenant_id)::uuid AND status = 'pending' AND deleted_at IS NULL;

-- name: TenantInviteForUpdate :one
SELECT tenant_id::text, user_id::text, role, status, expires_at
FROM profiles.tenant_invites
WHERE id = sqlc.arg(id)::uuid AND deleted_at IS NULL;

-- name: TenantInviteMarkExpired :exec
UPDATE profiles.tenant_invites
SET status = 'expired', acted_at = now(), updated_at = now()
WHERE id = sqlc.arg(id)::uuid;

-- name: TenantInviteSetStatus :exec
UPDATE profiles.tenant_invites
SET status = sqlc.arg(status), acted_at = now(), updated_at = now()
WHERE id = sqlc.arg(id)::uuid;
