-- Tenant + membership + role queries (core/service_tenants.go).

-- name: TenantBySlug :one
SELECT id::text, slug, is_personal, COALESCE(owner_user_id::text, '')::text AS owner_user_id
FROM profiles.tenants
WHERE slug = $1 AND deleted_at IS NULL;

-- TenantBySlugViaRename resolves a historical slug (issue #58). The
-- tenant_renames row's tenant_id always points at the live owner, so any
-- historical slug resolves to the tenant currently holding it; most recent
-- row wins (hard-delete + reuse).
-- name: TenantBySlugViaRename :one
SELECT o.id::text AS id, o.slug, o.is_personal, COALESCE(o.owner_user_id::text, '')::text AS owner_user_id
FROM profiles.tenant_renames r
JOIN profiles.tenants o ON o.id = r.tenant_id AND o.deleted_at IS NULL
WHERE r.from_slug = $1
ORDER BY r.renamed_at DESC
LIMIT 1;

-- name: TenantInsert :one
INSERT INTO profiles.tenants (id, slug, metadata)
VALUES (sqlc.arg(id)::uuid, $2, jsonb_build_object('namespace_state', 'registered_tenant', 'reserved', to_jsonb(false)))
RETURNING id::text, slug;

-- name: TenantRolesSeedOwnerMember :exec
INSERT INTO profiles.tenant_roles (tenant_id, role)
VALUES (sqlc.arg(tenant_id)::uuid, sqlc.arg(owner_role)), (sqlc.arg(tenant_id)::uuid, sqlc.arg(member_role))
ON CONFLICT (tenant_id, role) DO NOTHING;

-- name: TenantRolePermissionInsert :exec
INSERT INTO profiles.tenant_role_permissions (tenant_id, role, permission)
VALUES (sqlc.arg(tenant_id)::uuid, $2, $3)
ON CONFLICT DO NOTHING;

-- name: TenantMembershipUpsertRole :exec
INSERT INTO profiles.tenant_memberships (tenant_id, user_id, role)
VALUES (sqlc.arg(tenant_id)::uuid, sqlc.arg(user_id)::uuid, $3)
ON CONFLICT (tenant_id, user_id)
DO UPDATE SET role = EXCLUDED.role, deleted_at = NULL, updated_at = now();

-- name: TenantSlugAndPersonalByID :one
SELECT slug, is_personal FROM profiles.tenants
WHERE id = sqlc.arg(id)::uuid AND deleted_at IS NULL;

-- name: TenantLastRenamedAt :one
SELECT renamed_at
FROM   profiles.tenant_renames
WHERE  tenant_id = sqlc.arg(tenant_id)::uuid
ORDER  BY renamed_at DESC
LIMIT  1;

-- name: TenantRenameInsert :exec
INSERT INTO profiles.tenant_renames (tenant_id, from_slug)
VALUES (sqlc.arg(tenant_id)::uuid, $2);

-- name: TenantUpdateSlug :exec
UPDATE profiles.tenants SET slug = $1, updated_at = now()
WHERE id = sqlc.arg(id)::uuid AND deleted_at IS NULL;

-- name: TenantSlugsByUser :many
SELECT o.slug
FROM profiles.tenant_memberships m
JOIN profiles.tenants o ON o.id = m.tenant_id
WHERE m.user_id = sqlc.arg(user_id)::uuid AND m.deleted_at IS NULL AND o.deleted_at IS NULL
ORDER BY o.slug ASC;

-- TenantMemberAdd intentionally does NOT change role on conflict (re-adding
-- an existing member only revives a soft-deleted row).
-- name: TenantMemberAdd :exec
INSERT INTO profiles.tenant_memberships (tenant_id, user_id, role)
VALUES (sqlc.arg(tenant_id)::uuid, sqlc.arg(user_id)::uuid, 'member')
ON CONFLICT (tenant_id, user_id) DO UPDATE SET deleted_at = NULL, updated_at = now();

-- name: TenantMemberHasRole :one
SELECT EXISTS (
  SELECT 1
  FROM profiles.tenant_memberships
  WHERE tenant_id = sqlc.arg(tenant_id)::uuid AND user_id = sqlc.arg(user_id)::uuid AND role = $3 AND deleted_at IS NULL
);

-- name: TenantRoleMemberCount :one
SELECT COUNT(*)
FROM profiles.tenant_memberships
WHERE tenant_id = sqlc.arg(tenant_id)::uuid AND role = $2 AND deleted_at IS NULL;

-- name: TenantMemberSoftDelete :exec
UPDATE profiles.tenant_memberships SET deleted_at = now(), updated_at = now()
WHERE tenant_id = sqlc.arg(tenant_id)::uuid AND user_id = sqlc.arg(user_id)::uuid AND deleted_at IS NULL;

-- name: TenantRoleDefine :exec
INSERT INTO profiles.tenant_roles (tenant_id, role)
VALUES (sqlc.arg(tenant_id)::uuid, $2)
ON CONFLICT (tenant_id, role) DO NOTHING;

-- name: TenantRoleDelete :exec
DELETE FROM profiles.tenant_roles
WHERE tenant_id = sqlc.arg(tenant_id)::uuid AND role = $2;

-- name: TenantMembershipSetRole :exec
UPDATE profiles.tenant_memberships
SET role = sqlc.arg(role), updated_at = now()
WHERE tenant_id = sqlc.arg(tenant_id)::uuid
  AND user_id = sqlc.arg(user_id)::uuid
  AND deleted_at IS NULL
  AND EXISTS (SELECT 1 FROM profiles.tenant_roles WHERE tenant_id = sqlc.arg(tenant_id)::uuid AND role = sqlc.arg(role));

-- name: TenantMembershipResetRole :exec
UPDATE profiles.tenant_memberships
SET role = 'member', updated_at = now()
WHERE tenant_id = sqlc.arg(tenant_id)::uuid AND user_id = sqlc.arg(user_id)::uuid AND role = $3 AND deleted_at IS NULL;

-- name: TenantMemberRole :one
SELECT role
FROM profiles.tenant_memberships
WHERE tenant_id = sqlc.arg(tenant_id)::uuid AND user_id = sqlc.arg(user_id)::uuid AND deleted_at IS NULL;

-- name: TenantMembershipExists :one
SELECT EXISTS (
  SELECT 1 FROM profiles.tenant_memberships
  WHERE tenant_id = sqlc.arg(tenant_id)::uuid AND user_id = sqlc.arg(user_id)::uuid AND deleted_at IS NULL
);

-- name: TenantMemberIDs :many
SELECT user_id::text
FROM profiles.tenant_memberships
WHERE tenant_id = sqlc.arg(tenant_id)::uuid AND deleted_at IS NULL
ORDER BY user_id::text ASC;

-- name: TenantDefinedRoles :many
SELECT role
FROM profiles.tenant_roles
WHERE tenant_id = sqlc.arg(tenant_id)::uuid
ORDER BY role ASC;

-- Tenant RBAC role-permission queries (core/tenant_role_permissions.go).

-- name: TenantRolePermissions :many
SELECT permission FROM profiles.tenant_role_permissions
WHERE tenant_id = sqlc.arg(tenant_id)::uuid AND role = $2
ORDER BY permission ASC;

-- name: TenantRoleExists :one
SELECT EXISTS(SELECT 1 FROM profiles.tenant_roles WHERE tenant_id = sqlc.arg(tenant_id)::uuid AND role = $2);

-- name: TenantRolePermissionsDelete :exec
DELETE FROM profiles.tenant_role_permissions
WHERE tenant_id = sqlc.arg(tenant_id)::uuid AND role = $2;

-- name: TenantRoleHasPermissions :one
SELECT EXISTS(SELECT 1 FROM profiles.tenant_role_permissions WHERE tenant_id = sqlc.arg(tenant_id)::uuid AND role = $2);

-- Tenant issuer registry (core/service_tenant_issuers.go).

-- name: TenantIssuerUpsert :one
INSERT INTO profiles.tenant_issuers (tenant_id, issuer, jwks_uri, audiences, enabled)
VALUES (sqlc.arg(tenant_id)::uuid, $2, $3, $4, $5)
ON CONFLICT (tenant_id, issuer) DO UPDATE
  SET jwks_uri   = EXCLUDED.jwks_uri,
      audiences  = EXCLUDED.audiences,
      enabled    = EXCLUDED.enabled,
      updated_at = now()
RETURNING id::text, issuer, jwks_uri, audiences, enabled, created_at, updated_at;

-- name: TenantIssuerByIssuer :one
SELECT ti.id::text AS id, t.slug, ti.issuer, ti.jwks_uri, ti.audiences, ti.enabled, ti.created_at, ti.updated_at
FROM profiles.tenant_issuers ti
JOIN profiles.tenants t ON t.id = ti.tenant_id AND t.deleted_at IS NULL
WHERE ti.issuer = $1
ORDER BY ti.created_at ASC
LIMIT 1;

-- name: TenantIssuersAll :many
SELECT ti.id::text AS id, t.slug, ti.issuer, ti.jwks_uri, ti.audiences, ti.enabled, ti.created_at, ti.updated_at
FROM profiles.tenant_issuers ti
JOIN profiles.tenants t ON t.id = ti.tenant_id AND t.deleted_at IS NULL
ORDER BY t.slug ASC, ti.issuer ASC;

-- name: TenantIssuersEnabled :many
SELECT ti.id::text AS id, t.slug, ti.issuer, ti.jwks_uri, ti.audiences, ti.enabled, ti.created_at, ti.updated_at
FROM profiles.tenant_issuers ti
JOIN profiles.tenants t ON t.id = ti.tenant_id AND t.deleted_at IS NULL
WHERE ti.enabled = true
ORDER BY t.slug ASC, ti.issuer ASC;

-- name: TenantIssuerDelete :execrows
DELETE FROM profiles.tenant_issuers WHERE issuer = $1;

-- name: TenantSubjectTouch :one
INSERT INTO profiles.tenant_subjects (tenant_id, issuer, subject)
VALUES (sqlc.arg(tenant_id)::uuid, $2, $3)
ON CONFLICT (tenant_id, issuer, subject) DO UPDATE
  SET last_seen_at = now()
RETURNING id::text, tenant_id::text AS tenant_id, issuer, subject, created_at, last_seen_at;
