-- Org-admin (Layer-2 `platform:orgs:*`) queries — the /admin/orgs/* surface +
-- the anti-takeover `recover` reset. core/org_admin.go.

-- name: APIKeyRevokeAllByOrg :execrows
UPDATE profiles.service_tokens
SET revoked_at = now()
WHERE org_id = sqlc.arg(org_id)::uuid AND revoked_at IS NULL;

-- name: RemoteApplicationDisableAllByOrg :execrows
UPDATE profiles.remote_applications
SET enabled = false, updated_at = now()
WHERE org_id = sqlc.arg(org_id)::uuid AND enabled = true;

-- name: OrgMembershipsSoftDeleteAllByOrg :execrows
UPDATE profiles.org_memberships
SET deleted_at = now(), updated_at = now()
WHERE org_id = sqlc.arg(org_id)::uuid AND deleted_at IS NULL;

-- name: OrgsAdminList :many
SELECT id::text, slug, is_personal,
       COALESCE(owner_user_id::text, '')::text AS owner_user_id,
       created_at, deleted_at
FROM profiles.orgs
WHERE (sqlc.narg(search)::text IS NULL OR slug ILIKE '%' || sqlc.narg(search)::text || '%')
  AND (sqlc.arg(include_deleted)::bool OR deleted_at IS NULL)
ORDER BY created_at DESC
LIMIT sqlc.arg(page_limit)::int OFFSET sqlc.arg(page_offset)::int;

-- name: OrgSoftDelete :execrows
UPDATE profiles.orgs
SET deleted_at = now(), updated_at = now()
WHERE id = sqlc.arg(id)::uuid AND deleted_at IS NULL;

-- name: OrgRestore :execrows
UPDATE profiles.orgs
SET deleted_at = NULL, updated_at = now()
WHERE id = sqlc.arg(id)::uuid AND deleted_at IS NOT NULL;

-- name: OrgMemberCountByOrg :one
SELECT COUNT(*) FROM profiles.org_memberships
WHERE org_id = sqlc.arg(org_id)::uuid AND deleted_at IS NULL;

-- OrgDemoteAllOwners demotes every current owner-role member to the member
-- role. Used by transfer-owner to strip the prior owner(s) before assigning
-- the new one. Reports how many rows changed.
-- name: OrgDemoteAllOwners :execrows
UPDATE profiles.org_memberships
SET role = sqlc.arg(member_role), updated_at = now()
WHERE org_id = sqlc.arg(org_id)::uuid
  AND member_kind = 'user'
  AND role = sqlc.arg(owner_role)
  AND deleted_at IS NULL;
