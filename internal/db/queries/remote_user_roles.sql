-- Roles trusted issuers' users hold in groups (federated grants).

-- name: RemoteUserRoleBySubject :one
SELECT r.role
FROM group_remote_user_roles r
JOIN remote_users u ON u.id = r.remote_user_id
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

-- name: RemoteInvitationConsume :one
-- Redeems a pending invitation of the group for email, once.
UPDATE account_registration_invites
SET consumed_at = now()
WHERE id = sqlc.arg(id)::uuid AND permission_group_id = sqlc.arg(permission_group_id)::uuid AND email = sqlc.arg(email)::citext
  AND role IS NOT NULL AND consumed_at IS NULL AND revoked_at IS NULL AND expires_at > now()
RETURNING role;

-- name: RemoteUserRoleByID :one
SELECT role FROM group_remote_user_roles
WHERE permission_group_id = sqlc.arg(permission_group_id)::uuid AND remote_user_id = sqlc.arg(remote_user_id)::uuid
FOR UPDATE;
