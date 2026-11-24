-- Roles trusted issuers' users hold in groups (federated grants).

-- name: RemoteUserRoleBySubject :one
SELECT r.role, g.persona, cr.permissions AS custom_permissions
FROM group_remote_user_roles r
JOIN remote_users u ON u.id = r.remote_user_id
JOIN permission_groups g ON g.id = r.permission_group_id
LEFT JOIN group_custom_roles cr ON cr.permission_group_id = r.permission_group_id AND cr.role = r.role
WHERE r.permission_group_id = sqlc.arg(permission_group_id)::uuid
  AND u.issuer = sqlc.arg(issuer) AND u.subject = sqlc.arg(subject);

-- name: RemoteUserRoleUpsert :exec
INSERT INTO group_remote_user_roles (permission_group_id, remote_user_id, role, invitation_id)
VALUES (sqlc.arg(permission_group_id)::uuid, sqlc.arg(remote_user_id)::uuid, sqlc.arg(role), sqlc.narg(invitation_id)::uuid)
ON CONFLICT (permission_group_id, remote_user_id) DO UPDATE
  SET role = EXCLUDED.role, invitation_id = EXCLUDED.invitation_id, created_at = now();

-- name: RemoteUserRolesByGroup :many
SELECT r.remote_user_id::text AS remote_user_id, u.issuer, u.subject, u.email, r.role, r.created_at
FROM group_remote_user_roles r
JOIN remote_users u ON u.id = r.remote_user_id
WHERE r.permission_group_id = sqlc.arg(permission_group_id)::uuid
ORDER BY r.created_at, r.remote_user_id;

-- name: RemoteUserRoleDelete :execrows
DELETE FROM group_remote_user_roles
WHERE permission_group_id = sqlc.arg(permission_group_id)::uuid AND remote_user_id = sqlc.arg(remote_user_id)::uuid;

-- name: RemoteInvitationsPending :many
-- A group's email invitations with a role, pending for email.
SELECT id::text AS id, permission_group_id::text AS permission_group_id, role, email::text AS email, created_at, expires_at
FROM account_registration_invites
WHERE permission_group_id = sqlc.arg(permission_group_id)::uuid AND email = sqlc.arg(email)::citext
  AND role IS NOT NULL AND consumed_at IS NULL AND revoked_at IS NULL AND expires_at > now()
ORDER BY created_at, id;

-- name: RemoteInvitationForUpdate :one
-- A group's email invitation with a role, for email, locked for redemption.
SELECT i.id, g.id AS group_id, g.persona, COALESCE(i.role, '')::text AS role, i.consumed_at, i.expires_at, i.revoked_at,
  (i.invited_by IS NULL OR EXISTS(SELECT 1 FROM usable_users WHERE id = i.invited_by))::boolean AS issuer_live
FROM account_registration_invites i JOIN permission_groups g ON g.id = i.permission_group_id AND g.deleted_at IS NULL
WHERE i.id = sqlc.arg(id)::uuid AND i.permission_group_id = sqlc.arg(permission_group_id)::uuid AND i.email = sqlc.arg(email)::citext
  AND i.role IS NOT NULL
FOR UPDATE OF i;

-- name: RemoteUserRoleByID :one
SELECT role FROM group_remote_user_roles
WHERE permission_group_id = sqlc.arg(permission_group_id)::uuid AND remote_user_id = sqlc.arg(remote_user_id)::uuid
FOR UPDATE;
