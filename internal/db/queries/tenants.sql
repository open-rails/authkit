-- name: TenantByID :one
SELECT * FROM tenants WHERE id=sqlc.arg(id)::uuid;

-- An existing id returns its row unchanged; the caller compares its name.
-- name: TenantCreate :one
INSERT INTO tenants(id, slug) VALUES(sqlc.arg(id)::uuid, sqlc.arg(slug)::text)
ON CONFLICT(id) DO UPDATE SET id=EXCLUDED.id
RETURNING *;

-- name: LockTenantForRename :one
SELECT * FROM tenants WHERE id=sqlc.arg(id)::uuid FOR UPDATE;

-- name: RenameTenant :one
UPDATE tenants SET slug=sqlc.arg(slug)::text, slug_changed_at=now()
WHERE id=sqlc.arg(id)::uuid
RETURNING *;

-- name: InsertTenantSlugAlias :exec
INSERT INTO tenant_slug_aliases(slug, tenant_id, expires_at)
VALUES (
  sqlc.arg(slug)::text, sqlc.arg(tenant_id)::uuid,
  CASE WHEN sqlc.arg(forever)::boolean THEN NULL
       ELSE now() + sqlc.arg(retention_seconds)::float8 * interval '1 second' END
);

-- A live name or an unexpired former name; the row is the tenant as it is now.
-- name: TenantBySlugOrAlias :one
SELECT t.* FROM tenants t WHERE t.slug=sqlc.arg(slug)::text
UNION ALL
SELECT t.* FROM tenant_slug_aliases a JOIN tenants t ON t.id=a.tenant_id
WHERE a.slug=sqlc.arg(slug)::text AND (a.expires_at IS NULL OR a.expires_at > now())
LIMIT 1;

-- name: AccountTenant :one
SELECT tenant_id FROM users WHERE id=sqlc.arg(id)::uuid AND deleted_at IS NULL;
