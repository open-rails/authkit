-- Org + membership + role queries (core/service_orgs.go).

-- name: OrgBySlug :one
SELECT id::text, slug, is_personal, COALESCE(owner_user_id::text, '')::text AS owner_user_id
FROM profiles.orgs
WHERE slug = $1 AND deleted_at IS NULL;

-- OrgBySlugViaRename resolves a historical slug (issue #58). The
-- org_renames row's org_id always points at the live owner, so any
-- historical slug resolves to the org currently holding it; most recent
-- row wins (hard-delete + reuse).
-- name: OrgBySlugViaRename :one
SELECT o.id::text AS id, o.slug, o.is_personal, COALESCE(o.owner_user_id::text, '')::text AS owner_user_id
FROM profiles.org_renames r
JOIN profiles.orgs o ON o.id = r.org_id AND o.deleted_at IS NULL
WHERE r.from_slug = $1
ORDER BY r.renamed_at DESC
LIMIT 1;

-- name: OrgInsert :one
INSERT INTO profiles.orgs (id, slug, metadata)
VALUES (sqlc.arg(id)::uuid, $2, jsonb_build_object('namespace_state', 'registered_org', 'reserved', to_jsonb(false)))
RETURNING id::text, slug;

-- name: OrgRolesSeedOwnerMember :exec
INSERT INTO profiles.org_roles (org_id, role)
VALUES (sqlc.arg(org_id)::uuid, sqlc.arg(owner_role)), (sqlc.arg(org_id)::uuid, sqlc.arg(member_role))
ON CONFLICT (org_id, role) DO NOTHING;

-- name: OrgRolePermissionInsert :exec
INSERT INTO profiles.org_role_permissions (org_id, role, permission)
VALUES (sqlc.arg(org_id)::uuid, $2, $3)
ON CONFLICT DO NOTHING;

-- name: OrgMembershipUpsertRole :exec
INSERT INTO profiles.org_memberships (org_id, member_id, member_kind, role)
VALUES (sqlc.arg(org_id)::uuid, sqlc.arg(user_id)::uuid, 'user', $3)
ON CONFLICT (org_id, member_id, member_kind)
DO UPDATE SET role = EXCLUDED.role, deleted_at = NULL, updated_at = now();

-- name: OrgSlugAndPersonalByID :one
SELECT slug, is_personal FROM profiles.orgs
WHERE id = sqlc.arg(id)::uuid AND deleted_at IS NULL;

-- name: OrgLastRenamedAt :one
SELECT renamed_at
FROM   profiles.org_renames
WHERE  org_id = sqlc.arg(org_id)::uuid
ORDER  BY renamed_at DESC
LIMIT  1;

-- name: OrgRenameInsert :exec
INSERT INTO profiles.org_renames (org_id, from_slug)
VALUES (sqlc.arg(org_id)::uuid, $2);

-- name: OrgUpdateSlug :exec
UPDATE profiles.orgs SET slug = $1, updated_at = now()
WHERE id = sqlc.arg(id)::uuid AND deleted_at IS NULL;

-- name: OrgSlugsByUser :many
SELECT o.slug
FROM profiles.org_memberships m
JOIN profiles.orgs o ON o.id = m.org_id
WHERE m.member_id = sqlc.arg(user_id)::uuid AND m.member_kind = 'user' AND m.deleted_at IS NULL AND o.deleted_at IS NULL
ORDER BY o.slug ASC;

-- OrgMemberAdd intentionally does NOT change role on conflict (re-adding
-- an existing member only revives a soft-deleted row).
-- name: OrgMemberAdd :exec
INSERT INTO profiles.org_memberships (org_id, member_id, member_kind, role)
VALUES (sqlc.arg(org_id)::uuid, sqlc.arg(user_id)::uuid, 'user', 'member')
ON CONFLICT (org_id, member_id, member_kind) DO UPDATE SET deleted_at = NULL, updated_at = now();

-- name: OrgMemberHasRole :one
SELECT EXISTS (
  SELECT 1
  FROM profiles.org_memberships
  WHERE org_id = sqlc.arg(org_id)::uuid AND member_id = sqlc.arg(user_id)::uuid AND member_kind = 'user' AND role = $3 AND deleted_at IS NULL
);

-- name: OrgRoleMemberCount :one
SELECT COUNT(*)
FROM profiles.org_memberships
WHERE org_id = sqlc.arg(org_id)::uuid AND role = $2 AND deleted_at IS NULL;

-- name: OrgMemberSoftDelete :exec
UPDATE profiles.org_memberships SET deleted_at = now(), updated_at = now()
WHERE org_id = sqlc.arg(org_id)::uuid AND member_id = sqlc.arg(user_id)::uuid AND member_kind = 'user' AND deleted_at IS NULL;

-- name: OrgRoleDefine :exec
INSERT INTO profiles.org_roles (org_id, role)
VALUES (sqlc.arg(org_id)::uuid, $2)
ON CONFLICT (org_id, role) DO NOTHING;

-- name: OrgRoleDelete :exec
DELETE FROM profiles.org_roles
WHERE org_id = sqlc.arg(org_id)::uuid AND role = $2;

-- name: OrgMembershipSetRole :exec
UPDATE profiles.org_memberships
SET role = sqlc.arg(role), updated_at = now()
WHERE org_id = sqlc.arg(org_id)::uuid
  AND member_id = sqlc.arg(user_id)::uuid
  AND member_kind = 'user'
  AND deleted_at IS NULL
  AND EXISTS (SELECT 1 FROM profiles.org_roles WHERE org_id = sqlc.arg(org_id)::uuid AND role = sqlc.arg(role));

-- name: OrgMembershipResetRole :exec
UPDATE profiles.org_memberships
SET role = 'member', updated_at = now()
WHERE org_id = sqlc.arg(org_id)::uuid AND member_id = sqlc.arg(user_id)::uuid AND member_kind = 'user' AND role = $3 AND deleted_at IS NULL;

-- name: OrgMemberRole :one
SELECT role
FROM profiles.org_memberships
WHERE org_id = sqlc.arg(org_id)::uuid AND member_id = sqlc.arg(user_id)::uuid AND member_kind = 'user' AND deleted_at IS NULL;

-- name: OrgMembershipExists :one
SELECT EXISTS (
  SELECT 1 FROM profiles.org_memberships
  WHERE org_id = sqlc.arg(org_id)::uuid AND member_id = sqlc.arg(user_id)::uuid AND member_kind = 'user' AND deleted_at IS NULL
);

-- name: OrgMemberIDs :many
SELECT member_id::text
FROM profiles.org_memberships
WHERE org_id = sqlc.arg(org_id)::uuid AND member_kind = 'user' AND deleted_at IS NULL
ORDER BY member_id::text ASC;

-- Polymorphic remote_application memberships: a remote_app holds org roles
-- via the SAME org_memberships/org_roles machinery as users (#74).

-- name: OrgMembershipUpsertRolePrincipal :exec
INSERT INTO profiles.org_memberships (org_id, member_id, member_kind, role)
VALUES (sqlc.arg(org_id)::uuid, sqlc.arg(member_id)::uuid, sqlc.arg(member_kind), sqlc.arg(role))
ON CONFLICT (org_id, member_id, member_kind)
DO UPDATE SET role = EXCLUDED.role, deleted_at = NULL, updated_at = now();

-- name: OrgMemberSoftDeletePrincipal :exec
UPDATE profiles.org_memberships SET deleted_at = now(), updated_at = now()
WHERE org_id = sqlc.arg(org_id)::uuid AND member_id = sqlc.arg(member_id)::uuid AND member_kind = sqlc.arg(member_kind) AND deleted_at IS NULL;

-- name: OrgMemberRolePrincipal :one
SELECT role
FROM profiles.org_memberships
WHERE org_id = sqlc.arg(org_id)::uuid AND member_id = sqlc.arg(member_id)::uuid AND member_kind = sqlc.arg(member_kind) AND deleted_at IS NULL;

-- name: OrgRolesForPrincipal :many
SELECT o.slug, m.role
FROM profiles.org_memberships m
JOIN profiles.orgs o ON o.id = m.org_id AND o.deleted_at IS NULL
WHERE m.member_id = sqlc.arg(member_id)::uuid AND m.member_kind = sqlc.arg(member_kind) AND m.deleted_at IS NULL
ORDER BY o.slug ASC, m.role ASC;

-- name: OrgDefinedRoles :many
SELECT role
FROM profiles.org_roles
WHERE org_id = sqlc.arg(org_id)::uuid
ORDER BY role ASC;

-- Org RBAC role-permission queries (core/org_role_permissions.go).

-- name: OrgRolePermissions :many
SELECT permission FROM profiles.org_role_permissions
WHERE org_id = sqlc.arg(org_id)::uuid AND role = $2
ORDER BY permission ASC;

-- name: OrgRoleExists :one
SELECT EXISTS(SELECT 1 FROM profiles.org_roles WHERE org_id = sqlc.arg(org_id)::uuid AND role = $2);

-- name: OrgRolePermissionsDelete :exec
DELETE FROM profiles.org_role_permissions
WHERE org_id = sqlc.arg(org_id)::uuid AND role = $2;

-- name: OrgRoleHasPermissions :one
SELECT EXISTS(SELECT 1 FROM profiles.org_role_permissions WHERE org_id = sqlc.arg(org_id)::uuid AND role = $2);

-- Remote application registry (core/service_remote_applications.go). A
-- remote_application is the federation PRINCIPAL: it authenticates by signing
-- JWTs verified against its JWKS/public keys (#74).

-- name: RemoteApplicationUpsert :one
INSERT INTO profiles.remote_applications (slug, org_id, issuer, jwks_uri, mode, public_keys, audiences, allowed_origins, enabled)
VALUES (sqlc.arg(slug), sqlc.narg(org_id)::uuid, sqlc.arg(issuer), sqlc.arg(jwks_uri), sqlc.arg(mode), sqlc.arg(public_keys), sqlc.arg(audiences), sqlc.arg(allowed_origins), sqlc.arg(enabled))
ON CONFLICT (issuer) DO UPDATE
  SET slug          = EXCLUDED.slug,
      org_id     = EXCLUDED.org_id,
      jwks_uri      = EXCLUDED.jwks_uri,
      mode          = EXCLUDED.mode,
      public_keys   = EXCLUDED.public_keys,
      audiences     = EXCLUDED.audiences,
      allowed_origins = EXCLUDED.allowed_origins,
      enabled       = EXCLUDED.enabled,
      updated_at    = now()
RETURNING id::text, slug, COALESCE(org_id::text, '')::text AS org_id, issuer, jwks_uri, mode, public_keys, audiences, allowed_origins, enabled, created_at, updated_at;

-- name: RemoteApplicationByIssuer :one
SELECT id::text, slug, COALESCE(org_id::text, '')::text AS org_id, issuer, jwks_uri, mode, public_keys, audiences, allowed_origins, enabled, created_at, updated_at
FROM profiles.remote_applications
WHERE issuer = $1 AND deleted_at IS NULL;

-- name: RemoteApplicationBySlug :one
SELECT id::text, slug, COALESCE(org_id::text, '')::text AS org_id, issuer, jwks_uri, mode, public_keys, audiences, allowed_origins, enabled, created_at, updated_at
FROM profiles.remote_applications
WHERE slug = $1 AND deleted_at IS NULL;

-- name: RemoteApplicationsAll :many
SELECT id::text, slug, COALESCE(org_id::text, '')::text AS org_id, issuer, jwks_uri, mode, public_keys, audiences, allowed_origins, enabled, created_at, updated_at
FROM profiles.remote_applications
WHERE deleted_at IS NULL
ORDER BY slug ASC;

-- name: RemoteApplicationsEnabled :many
SELECT id::text, slug, COALESCE(org_id::text, '')::text AS org_id, issuer, jwks_uri, mode, public_keys, audiences, allowed_origins, enabled, created_at, updated_at
FROM profiles.remote_applications
WHERE enabled = true AND deleted_at IS NULL
ORDER BY slug ASC;

-- name: RemoteApplicationDelete :execrows
DELETE FROM profiles.remote_applications WHERE issuer = $1;

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
