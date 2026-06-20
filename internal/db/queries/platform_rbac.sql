-- Platform RBAC queries (#95, Layer 2 — the ClusterRole plane). core/platform_rbac.go.

-- name: PlatformRoleUpsert :exec
INSERT INTO profiles.platform_roles (role)
VALUES ($1)
ON CONFLICT (role) DO NOTHING;

-- name: PlatformRoleExists :one
SELECT EXISTS (SELECT 1 FROM profiles.platform_roles WHERE role = $1);

-- name: PlatformRoleDelete :execrows
DELETE FROM profiles.platform_roles WHERE role = $1;

-- name: PlatformRolesList :many
SELECT role FROM profiles.platform_roles ORDER BY role;

-- name: PlatformRolePermissions :many
SELECT permission FROM profiles.platform_role_permissions WHERE role = $1 ORDER BY permission;

-- name: PlatformRolePermissionInsert :exec
INSERT INTO profiles.platform_role_permissions (role, permission)
VALUES ($1, $2)
ON CONFLICT (role, permission) DO NOTHING;

-- name: PlatformRolePermissionsDelete :exec
DELETE FROM profiles.platform_role_permissions WHERE role = $1;

-- name: PlatformUserRoleInsert :exec
INSERT INTO profiles.platform_user_roles (user_id, role)
VALUES ($1, $2)
ON CONFLICT (user_id, role) DO NOTHING;

-- name: PlatformUserRoleDelete :execrows
DELETE FROM profiles.platform_user_roles WHERE user_id = $1 AND role = $2;

-- name: PlatformUserRoles :many
SELECT role FROM profiles.platform_user_roles WHERE user_id = $1 ORDER BY role;

-- name: PlatformUserPermissions :many
-- The efficient single indexed-JOIN per-request resolution (#95): every platform
-- permission a user holds across all their platform roles. A regular user has 0
-- rows in platform_user_roles, so this returns empty without touching the
-- permission table.
SELECT DISTINCT p.permission
FROM profiles.platform_user_roles ur
JOIN profiles.platform_role_permissions p ON p.role = ur.role
WHERE ur.user_id = $1;

-- name: PlatformUserHasPermissionToken :one
-- Hot authz path: one indexed query from user + candidate grant tokens to
-- "allowed?". No full permission-set materialization on every platform gate.
SELECT EXISTS (
  SELECT 1
  FROM profiles.platform_user_roles ur
  JOIN profiles.platform_role_permissions p
    ON p.role = ur.role
   AND p.permission = ANY(sqlc.arg(permissions)::text[])
  WHERE ur.user_id = sqlc.arg(user_id)::uuid
);

-- name: PlatformUserRoleMembers :many
-- WHO holds a given platform role (the platform-admin roster read).
SELECT user_id FROM profiles.platform_user_roles WHERE role = $1 ORDER BY user_id;
