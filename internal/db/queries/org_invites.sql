-- Org invite queries (core/service_org_invites.go).

-- name: OrgInviteInsert :one
INSERT INTO profiles.org_invites (id, org_id, user_id, invited_by, role, status, expires_at)
VALUES (sqlc.arg(id)::uuid, sqlc.arg(org_id)::uuid, sqlc.arg(user_id)::uuid, sqlc.arg(invited_by)::uuid, $5, 'pending', $6)
RETURNING id::text, user_id::text, invited_by::text, role, status, expires_at, acted_at, created_at;

-- name: OrgInvitesByOrg :many
SELECT id::text, user_id::text, invited_by::text, role, status, expires_at, acted_at, created_at
FROM profiles.org_invites
WHERE org_id = sqlc.arg(org_id)::uuid AND deleted_at IS NULL
ORDER BY created_at DESC;

-- name: OrgInvitesByOrgStatus :many
SELECT id::text, user_id::text, invited_by::text, role, status, expires_at, acted_at, created_at
FROM profiles.org_invites
WHERE org_id = sqlc.arg(org_id)::uuid AND status = $2 AND deleted_at IS NULL
ORDER BY created_at DESC;

-- name: OrgInvitesByUser :many
SELECT i.id::text AS id, o.slug, i.user_id::text AS user_id, i.invited_by::text AS invited_by, i.role, i.status, i.expires_at, i.acted_at, i.created_at
FROM profiles.org_invites i
JOIN profiles.orgs o ON o.id = i.org_id
WHERE i.user_id = sqlc.arg(user_id)::uuid AND i.deleted_at IS NULL AND o.deleted_at IS NULL
ORDER BY i.created_at DESC;

-- name: OrgInvitesByUserStatus :many
SELECT i.id::text AS id, o.slug, i.user_id::text AS user_id, i.invited_by::text AS invited_by, i.role, i.status, i.expires_at, i.acted_at, i.created_at
FROM profiles.org_invites i
JOIN profiles.orgs o ON o.id = i.org_id
WHERE i.user_id = sqlc.arg(user_id)::uuid AND i.status = $2 AND i.deleted_at IS NULL AND o.deleted_at IS NULL
ORDER BY i.created_at DESC;

-- name: OrgInviteRevoke :execrows
UPDATE profiles.org_invites
SET status = 'revoked', acted_at = now(), updated_at = now()
WHERE id = sqlc.arg(id)::uuid AND org_id = sqlc.arg(org_id)::uuid AND status = 'pending' AND deleted_at IS NULL;

-- name: OrgInviteForUpdate :one
SELECT org_id::text, user_id::text, role, status, expires_at
FROM profiles.org_invites
WHERE id = sqlc.arg(id)::uuid AND deleted_at IS NULL;

-- name: OrgInviteMarkExpired :exec
UPDATE profiles.org_invites
SET status = 'expired', acted_at = now(), updated_at = now()
WHERE id = sqlc.arg(id)::uuid;

-- name: OrgInviteSetStatus :exec
UPDATE profiles.org_invites
SET status = sqlc.arg(status), acted_at = now(), updated_at = now()
WHERE id = sqlc.arg(id)::uuid;
