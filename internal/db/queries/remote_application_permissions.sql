-- Remote application direct-permission grants (core/remote_application_permissions.go, #76).
-- STORED authority for a JWKS principal acting as itself; mirrors the
-- service_token_permissions grant.

-- name: RemoteApplicationPermissionInsert :exec
INSERT INTO profiles.remote_application_permissions (remote_application_id, permission)
VALUES (sqlc.arg(remote_application_id)::uuid, $2)
ON CONFLICT (remote_application_id, permission) DO NOTHING;

-- name: RemoteApplicationPermissionDelete :execrows
DELETE FROM profiles.remote_application_permissions
WHERE remote_application_id = sqlc.arg(remote_application_id)::uuid AND permission = $2;

-- name: RemoteApplicationPermissions :many
SELECT permission
FROM profiles.remote_application_permissions
WHERE remote_application_id = sqlc.arg(remote_application_id)::uuid
ORDER BY permission ASC;
