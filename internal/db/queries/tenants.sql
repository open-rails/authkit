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
INSERT INTO profiles.tenant_memberships (tenant_id, member_id, member_kind, role)
VALUES (sqlc.arg(tenant_id)::uuid, sqlc.arg(user_id)::uuid, 'user', $3)
ON CONFLICT (tenant_id, member_id, member_kind)
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
WHERE m.member_id = sqlc.arg(user_id)::uuid AND m.member_kind = 'user' AND m.deleted_at IS NULL AND o.deleted_at IS NULL
ORDER BY o.slug ASC;

-- TenantMemberAdd intentionally does NOT change role on conflict (re-adding
-- an existing member only revives a soft-deleted row).
-- name: TenantMemberAdd :exec
INSERT INTO profiles.tenant_memberships (tenant_id, member_id, member_kind, role)
VALUES (sqlc.arg(tenant_id)::uuid, sqlc.arg(user_id)::uuid, 'user', 'member')
ON CONFLICT (tenant_id, member_id, member_kind) DO UPDATE SET deleted_at = NULL, updated_at = now();

-- name: TenantMemberHasRole :one
SELECT EXISTS (
  SELECT 1
  FROM profiles.tenant_memberships
  WHERE tenant_id = sqlc.arg(tenant_id)::uuid AND member_id = sqlc.arg(user_id)::uuid AND member_kind = 'user' AND role = $3 AND deleted_at IS NULL
);

-- name: TenantRoleMemberCount :one
SELECT COUNT(*)
FROM profiles.tenant_memberships
WHERE tenant_id = sqlc.arg(tenant_id)::uuid AND role = $2 AND deleted_at IS NULL;

-- name: TenantMemberSoftDelete :exec
UPDATE profiles.tenant_memberships SET deleted_at = now(), updated_at = now()
WHERE tenant_id = sqlc.arg(tenant_id)::uuid AND member_id = sqlc.arg(user_id)::uuid AND member_kind = 'user' AND deleted_at IS NULL;

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
  AND member_id = sqlc.arg(user_id)::uuid
  AND member_kind = 'user'
  AND deleted_at IS NULL
  AND EXISTS (SELECT 1 FROM profiles.tenant_roles WHERE tenant_id = sqlc.arg(tenant_id)::uuid AND role = sqlc.arg(role));

-- name: TenantMembershipResetRole :exec
UPDATE profiles.tenant_memberships
SET role = 'member', updated_at = now()
WHERE tenant_id = sqlc.arg(tenant_id)::uuid AND member_id = sqlc.arg(user_id)::uuid AND member_kind = 'user' AND role = $3 AND deleted_at IS NULL;

-- name: TenantMemberRole :one
SELECT role
FROM profiles.tenant_memberships
WHERE tenant_id = sqlc.arg(tenant_id)::uuid AND member_id = sqlc.arg(user_id)::uuid AND member_kind = 'user' AND deleted_at IS NULL;

-- name: TenantMembershipExists :one
SELECT EXISTS (
  SELECT 1 FROM profiles.tenant_memberships
  WHERE tenant_id = sqlc.arg(tenant_id)::uuid AND member_id = sqlc.arg(user_id)::uuid AND member_kind = 'user' AND deleted_at IS NULL
);

-- name: TenantMemberIDs :many
SELECT member_id::text
FROM profiles.tenant_memberships
WHERE tenant_id = sqlc.arg(tenant_id)::uuid AND member_kind = 'user' AND deleted_at IS NULL
ORDER BY member_id::text ASC;

-- Polymorphic remote_application memberships: a remote_app holds tenant roles
-- via the SAME tenant_memberships/tenant_roles machinery as users (#74).

-- name: TenantMembershipUpsertRolePrincipal :exec
INSERT INTO profiles.tenant_memberships (tenant_id, member_id, member_kind, role)
VALUES (sqlc.arg(tenant_id)::uuid, sqlc.arg(member_id)::uuid, sqlc.arg(member_kind), sqlc.arg(role))
ON CONFLICT (tenant_id, member_id, member_kind)
DO UPDATE SET role = EXCLUDED.role, deleted_at = NULL, updated_at = now();

-- name: TenantMemberSoftDeletePrincipal :exec
UPDATE profiles.tenant_memberships SET deleted_at = now(), updated_at = now()
WHERE tenant_id = sqlc.arg(tenant_id)::uuid AND member_id = sqlc.arg(member_id)::uuid AND member_kind = sqlc.arg(member_kind) AND deleted_at IS NULL;

-- name: TenantMemberRolePrincipal :one
SELECT role
FROM profiles.tenant_memberships
WHERE tenant_id = sqlc.arg(tenant_id)::uuid AND member_id = sqlc.arg(member_id)::uuid AND member_kind = sqlc.arg(member_kind) AND deleted_at IS NULL;

-- name: TenantRolesForPrincipal :many
SELECT o.slug, m.role
FROM profiles.tenant_memberships m
JOIN profiles.tenants o ON o.id = m.tenant_id AND o.deleted_at IS NULL
WHERE m.member_id = sqlc.arg(member_id)::uuid AND m.member_kind = sqlc.arg(member_kind) AND m.deleted_at IS NULL
ORDER BY o.slug ASC, m.role ASC;

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

-- Remote application registry (core/service_remote_applications.go). A
-- remote_application is the federation PRINCIPAL: it authenticates by signing
-- JWTs verified against its JWKS/public keys (#74).

-- name: RemoteApplicationUpsert :one
INSERT INTO profiles.remote_applications (slug, owner_user_id, tenant_id, issuer, jwks_uri, mode, public_keys, audiences, enabled)
VALUES ($1, sqlc.narg(owner_user_id)::uuid, sqlc.narg(tenant_id)::uuid, $4, $5, $6, $7, $8, $9)
ON CONFLICT (issuer) DO UPDATE
  SET slug          = EXCLUDED.slug,
      owner_user_id = EXCLUDED.owner_user_id,
      tenant_id     = EXCLUDED.tenant_id,
      jwks_uri      = EXCLUDED.jwks_uri,
      mode          = EXCLUDED.mode,
      public_keys   = EXCLUDED.public_keys,
      audiences     = EXCLUDED.audiences,
      enabled       = EXCLUDED.enabled,
      updated_at    = now()
RETURNING id::text, slug, COALESCE(owner_user_id::text, '')::text AS owner_user_id, COALESCE(tenant_id::text, '')::text AS tenant_id, issuer, jwks_uri, mode, public_keys, audiences, enabled, created_at, updated_at;

-- name: RemoteApplicationByIssuer :one
SELECT id::text, slug, COALESCE(owner_user_id::text, '')::text AS owner_user_id, COALESCE(tenant_id::text, '')::text AS tenant_id, issuer, jwks_uri, mode, public_keys, audiences, enabled, created_at, updated_at
FROM profiles.remote_applications
WHERE issuer = $1 AND deleted_at IS NULL;

-- name: RemoteApplicationBySlug :one
SELECT id::text, slug, COALESCE(owner_user_id::text, '')::text AS owner_user_id, COALESCE(tenant_id::text, '')::text AS tenant_id, issuer, jwks_uri, mode, public_keys, audiences, enabled, created_at, updated_at
FROM profiles.remote_applications
WHERE slug = $1 AND deleted_at IS NULL;

-- name: RemoteApplicationsAll :many
SELECT id::text, slug, COALESCE(owner_user_id::text, '')::text AS owner_user_id, COALESCE(tenant_id::text, '')::text AS tenant_id, issuer, jwks_uri, mode, public_keys, audiences, enabled, created_at, updated_at
FROM profiles.remote_applications
WHERE deleted_at IS NULL
ORDER BY slug ASC;

-- name: RemoteApplicationsEnabled :many
SELECT id::text, slug, COALESCE(owner_user_id::text, '')::text AS owner_user_id, COALESCE(tenant_id::text, '')::text AS tenant_id, issuer, jwks_uri, mode, public_keys, audiences, enabled, created_at, updated_at
FROM profiles.remote_applications
WHERE enabled = true AND deleted_at IS NULL
ORDER BY slug ASC;

-- name: RemoteApplicationDelete :execrows
DELETE FROM profiles.remote_applications WHERE issuer = $1;

-- name: TenantSubjectTouch :one
INSERT INTO profiles.tenant_subjects (remote_application_id, issuer, subject)
VALUES (sqlc.arg(remote_application_id)::uuid, $2, $3)
ON CONFLICT (remote_application_id, issuer, subject) DO UPDATE
  SET last_seen_at = now()
RETURNING id::text, remote_application_id::text AS remote_application_id, issuer, subject, created_at, last_seen_at;

-- name: TenantSubjectsByApp :many
SELECT id::text, remote_application_id::text AS remote_application_id, issuer, subject, created_at, last_seen_at
FROM profiles.tenant_subjects
WHERE remote_application_id = sqlc.arg(remote_application_id)::uuid
ORDER BY last_seen_at DESC;

-- Attribute definition registry (#75): REFERENCE-mode opaque definitions.

-- name: RemoteAppAttributeDefUpsert :one
INSERT INTO profiles.remote_application_attribute_defs (remote_application_id, key, version, definition)
VALUES (sqlc.arg(remote_application_id)::uuid, $2, $3, $4)
ON CONFLICT (remote_application_id, key, version) DO UPDATE
  SET definition = EXCLUDED.definition, updated_at = now()
RETURNING remote_application_id::text AS remote_application_id, key, version, definition, created_at, updated_at;

-- name: RemoteAppAttributeDefGet :one
SELECT remote_application_id::text AS remote_application_id, key, version, definition, created_at, updated_at
FROM profiles.remote_application_attribute_defs
WHERE remote_application_id = sqlc.arg(remote_application_id)::uuid AND key = $2 AND version = $3;

-- name: RemoteAppAttributeDefGetLatest :one
SELECT remote_application_id::text AS remote_application_id, key, version, definition, created_at, updated_at
FROM profiles.remote_application_attribute_defs
WHERE remote_application_id = sqlc.arg(remote_application_id)::uuid AND key = $2
ORDER BY version DESC
LIMIT 1;

-- name: RemoteAppAttributeDefsList :many
SELECT remote_application_id::text AS remote_application_id, key, version, definition, created_at, updated_at
FROM profiles.remote_application_attribute_defs
WHERE remote_application_id = sqlc.arg(remote_application_id)::uuid
ORDER BY key ASC, version DESC;

-- name: RemoteAppAttributeDefDelete :execrows
DELETE FROM profiles.remote_application_attribute_defs
WHERE remote_application_id = sqlc.arg(remote_application_id)::uuid AND key = $2;
