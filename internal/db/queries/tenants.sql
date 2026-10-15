-- name: TenantByID :one
SELECT * FROM tenants WHERE id=sqlc.arg(id)::uuid;

-- name: TenantCreate :one
INSERT INTO tenants(id) VALUES(sqlc.arg(id)::uuid)
ON CONFLICT(id) DO UPDATE SET id=EXCLUDED.id
RETURNING *;

-- name: AccountTenant :one
SELECT tenant_id FROM users WHERE id=sqlc.arg(id)::uuid AND deleted_at IS NULL;
