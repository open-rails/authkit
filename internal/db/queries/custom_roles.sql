-- Custom roles (#448): roles a group defines at run time. Checks read them
-- joined into the assignment they resolve; these serve their management.

-- name: CustomRolesByGroup :many
SELECT role, permissions, created_at, updated_at FROM group_custom_roles
WHERE permission_group_id = sqlc.arg(group_id)::uuid ORDER BY role;

-- name: CustomRoleByName :one
SELECT role, permissions, created_at, updated_at FROM group_custom_roles
WHERE permission_group_id = sqlc.arg(group_id)::uuid AND role = sqlc.arg(role)::text;

-- name: CustomRoleCount :one
SELECT count(*)::bigint FROM group_custom_roles WHERE permission_group_id = sqlc.arg(group_id)::uuid;

-- name: CustomRoleInsert :one
INSERT INTO group_custom_roles (permission_group_id, role, permissions)
VALUES (sqlc.arg(group_id)::uuid, sqlc.arg(role)::text, sqlc.arg(permissions)::text[])
ON CONFLICT DO NOTHING
RETURNING created_at, updated_at;

-- name: CustomRoleUpdate :one
UPDATE group_custom_roles SET permissions = sqlc.arg(permissions)::text[], updated_at = now()
WHERE permission_group_id = sqlc.arg(group_id)::uuid AND role = sqlc.arg(role)::text
RETURNING created_at, updated_at;

-- name: CustomRoleDelete :exec
DELETE FROM group_custom_roles WHERE permission_group_id = sqlc.arg(group_id)::uuid AND role = sqlc.arg(role)::text;

-- name: CustomRoleHolders :one
-- Who holds the role in the group: members (users, remote users and pending
-- invitations), credentials (live API keys, applications and role maps),
-- machines (API keys and applications, which present no second factor) and
-- users with no second factor.
SELECT
  (EXISTS(SELECT 1 FROM group_user_roles r WHERE r.permission_group_id = sqlc.arg(group_id)::uuid AND r.role = sqlc.arg(role)::text)
   OR EXISTS(SELECT 1 FROM group_remote_user_roles r WHERE r.permission_group_id = sqlc.arg(group_id)::uuid AND r.role = sqlc.arg(role)::text)
   OR EXISTS(SELECT 1 FROM group_invite_links l WHERE l.permission_group_id = sqlc.arg(group_id)::uuid AND l.role = sqlc.arg(role)::text
     AND l.revoked_at IS NULL AND l.redeemed_at IS NULL AND (l.expires_at IS NULL OR l.expires_at > now()))
   OR EXISTS(SELECT 1 FROM account_registration_invites a WHERE a.permission_group_id = sqlc.arg(group_id)::uuid AND a.role = sqlc.arg(role)::text
     AND a.revoked_at IS NULL AND a.consumed_at IS NULL AND a.expires_at > now()))::boolean AS members,
  (EXISTS(SELECT 1 FROM api_keys k WHERE k.permission_group_id = sqlc.arg(group_id)::uuid AND k.role = sqlc.arg(role)::text
     AND k.revoked_at IS NULL AND (k.expires_at IS NULL OR k.expires_at > now()))
   OR EXISTS(SELECT 1 FROM group_remote_application_roles r WHERE r.permission_group_id = sqlc.arg(group_id)::uuid AND r.role = sqlc.arg(role)::text)
   OR EXISTS(SELECT 1 FROM remote_applications a, jsonb_each_text(a.role_map) m
     WHERE a.permission_group_id = sqlc.arg(group_id)::uuid AND m.value = sqlc.arg(role)::text))::boolean AS credentials,
  (EXISTS(SELECT 1 FROM api_keys k WHERE k.permission_group_id = sqlc.arg(group_id)::uuid AND k.role = sqlc.arg(role)::text
     AND k.revoked_at IS NULL AND (k.expires_at IS NULL OR k.expires_at > now()))
   OR EXISTS(SELECT 1 FROM group_remote_application_roles r WHERE r.permission_group_id = sqlc.arg(group_id)::uuid AND r.role = sqlc.arg(role)::text))::boolean AS machines,
  EXISTS(SELECT 1 FROM group_user_roles r WHERE r.permission_group_id = sqlc.arg(group_id)::uuid AND r.role = sqlc.arg(role)::text
    AND NOT EXISTS(SELECT 1 FROM mfa_factors f WHERE f.user_id = r.user_id))::boolean AS users_without_mfa;

-- name: CustomRoleUsersRemove :many
DELETE FROM group_user_roles WHERE permission_group_id = sqlc.arg(group_id)::uuid AND role = sqlc.arg(role)::text
RETURNING user_id::text;

-- name: CustomRoleApplicationsRemove :many
DELETE FROM group_remote_application_roles WHERE permission_group_id = sqlc.arg(group_id)::uuid AND role = sqlc.arg(role)::text
RETURNING remote_application_id::text;

-- name: CustomRoleRemoteUsersRemove :exec
DELETE FROM group_remote_user_roles WHERE permission_group_id = sqlc.arg(group_id)::uuid AND role = sqlc.arg(role)::text;

-- name: CustomRoleCredentialsRevoke :exec
-- Revokes the API keys and invitations carrying the role, and drops it from
-- role maps.
WITH keys AS (
  UPDATE api_keys SET revoked_at = now()
  WHERE permission_group_id = sqlc.arg(group_id)::uuid AND role = sqlc.arg(role)::text AND revoked_at IS NULL
), links AS (
  UPDATE group_invite_links SET revoked_at = now()
  WHERE permission_group_id = sqlc.arg(group_id)::uuid AND role = sqlc.arg(role)::text AND revoked_at IS NULL AND redeemed_at IS NULL
), invites AS (
  UPDATE account_registration_invites SET revoked_at = now()
  WHERE permission_group_id = sqlc.arg(group_id)::uuid AND role = sqlc.arg(role)::text AND revoked_at IS NULL AND consumed_at IS NULL
)
UPDATE remote_applications a SET updated_at = now(), role_map = NULLIF(
  (SELECT COALESCE(jsonb_object_agg(m.key, m.value), '{}'::jsonb) FROM jsonb_each_text(a.role_map) m WHERE m.value <> sqlc.arg(role)::text),
  '{}'::jsonb)
WHERE a.permission_group_id = sqlc.arg(group_id)::uuid
  AND EXISTS(SELECT 1 FROM jsonb_each_text(a.role_map) m WHERE m.value = sqlc.arg(role)::text);
