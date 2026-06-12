-- Global (platform) role queries (core/service.go).

-- name: GlobalRoleSlugsByUser :many
SELECT r.slug
FROM profiles.global_user_roles ur
JOIN profiles.global_roles r ON ur.role_id = r.id
WHERE ur.user_id = $1 AND r.deleted_at IS NULL;

-- name: GlobalRoleIDBySlug :one
SELECT id FROM profiles.global_roles WHERE slug = $1;

-- name: GlobalUserRoleInsert :exec
INSERT INTO profiles.global_user_roles (id, user_id, role_id)
VALUES ($1, $2, $3)
ON CONFLICT (user_id, role_id) DO NOTHING;

-- name: GlobalRoleUpsert :exec
INSERT INTO profiles.global_roles (name, slug, description)
VALUES ($1, $2, $3)
ON CONFLICT (slug) DO UPDATE SET
  name = EXCLUDED.name,
  description = EXCLUDED.description,
  updated_at = NOW(),
  deleted_at = NULL;

-- name: GlobalUserRoleDeleteBySlug :execrows
DELETE FROM profiles.global_user_roles ur
USING profiles.global_roles r
WHERE ur.role_id = r.id AND ur.user_id = $1 AND r.slug = $2 AND r.deleted_at IS NULL;

-- name: GlobalAdminRoleIDForUpdate :one
SELECT id FROM profiles.global_roles WHERE slug = 'admin' AND deleted_at IS NULL FOR UPDATE;

-- name: GlobalUserRoleExists :one
SELECT EXISTS (SELECT 1 FROM profiles.global_user_roles WHERE user_id = $1 AND role_id = $2);

-- name: GlobalActiveAdminCount :one
SELECT COUNT(*)
FROM profiles.global_user_roles ur
JOIN profiles.users u ON u.id = ur.user_id
WHERE ur.role_id = $1
  AND u.deleted_at IS NULL
  AND u.banned_at IS NULL;

-- name: GlobalUserRoleDelete :execrows
DELETE FROM profiles.global_user_roles WHERE user_id = $1 AND role_id = $2;

-- name: GlobalUserHasActiveRole :one
SELECT EXISTS (
  SELECT 1 FROM profiles.global_user_roles ur
  JOIN profiles.global_roles r ON ur.role_id = r.id
  WHERE ur.user_id = sqlc.arg(user_id) AND r.slug = sqlc.arg(slug)
    AND r.deleted_at IS NULL
    AND EXISTS (
      SELECT 1 FROM profiles.users u
      WHERE u.id = sqlc.arg(user_id) AND u.deleted_at IS NULL AND u.banned_at IS NULL
    )
);
