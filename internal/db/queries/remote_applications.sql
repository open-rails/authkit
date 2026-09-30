-- Remote application registry. A
-- remote_application is the federation PRINCIPAL: it authenticates by signing
-- JWTs verified against its JWKS/public keys (#74).
--
-- The controlling group is addressed as permission_group_id throughout. Every
-- read returns the whole row: db.RemoteApplication.

-- name: RemoteApplicationUpsert :one
INSERT INTO remote_applications (permission_group_id, issuer, jwks_uri, mode, public_keys, enabled)
VALUES (sqlc.arg(permission_group_id)::uuid, sqlc.arg(issuer), sqlc.arg(jwks_uri), sqlc.arg(mode), sqlc.arg(public_keys), sqlc.arg(enabled))
ON CONFLICT (issuer) DO UPDATE
  SET jwks_uri      = EXCLUDED.jwks_uri,
      mode          = EXCLUDED.mode,
      public_keys   = EXCLUDED.public_keys,
      enabled       = EXCLUDED.enabled,
      updated_at    = now()
WHERE remote_applications.permission_group_id = EXCLUDED.permission_group_id
RETURNING *;

-- name: RemoteApplicationByID :one
SELECT * FROM remote_applications WHERE id = $1;

-- name: RemoteApplicationByIssuer :one
SELECT * FROM remote_applications WHERE issuer = $1;

-- name: RemoteApplicationsEnabled :many
SELECT * FROM remote_applications WHERE enabled = true ORDER BY issuer;

-- name: RemoteApplicationsByGroup :many
-- Newest first, keyset-paged by id.
SELECT * FROM remote_applications
WHERE permission_group_id = sqlc.arg(permission_group_id)::uuid
  AND (sqlc.narg(after_id)::uuid IS NULL OR id < sqlc.narg(after_id)::uuid)
ORDER BY id DESC
LIMIT sqlc.arg(max_rows);

-- name: RemoteApplicationDelete :execrows
DELETE FROM remote_applications WHERE issuer = $1;

-- name: RemoteApplicationByIDForUpdate :one
SELECT * FROM remote_applications WHERE id = $1 FOR UPDATE;

-- name: RemoteApplicationSetTrustRoot :exec
UPDATE remote_applications SET trust_root = sqlc.arg(trust_root) WHERE id = sqlc.arg(id)::uuid;

-- name: RemoteApplicationSetRegistrar :exec
UPDATE remote_applications SET registered_by = sqlc.arg(registered_by)::uuid WHERE id = sqlc.arg(id)::uuid;

-- name: RemoteApplicationsClearRegistrar :exec
UPDATE remote_applications SET registered_by = NULL, updated_at = now() WHERE registered_by = sqlc.arg(user_id)::uuid;

-- name: RemoteApplicationControlRoles :many
-- The roles an application holds in live groups.
SELECT g.id::text AS group_id, g.persona, r.role
FROM group_remote_application_roles r
JOIN permission_groups g ON g.id = r.permission_group_id
WHERE r.remote_application_id = sqlc.arg(remote_application_id)::uuid AND g.deleted_at IS NULL
ORDER BY g.id;

-- name: RemoteApplicationAuthority :one
-- An enabled application in a live group, whose registrar (if a group
-- registered it) is usable.
SELECT ra.permission_group_id::text AS permission_group_id, pg.persona
FROM remote_applications ra
JOIN permission_groups pg ON pg.id = ra.permission_group_id
WHERE ra.id = sqlc.arg(id)::uuid AND ra.enabled AND pg.deleted_at IS NULL
  AND (ra.trust_root <> 'user' OR EXISTS (SELECT 1 FROM usable_users WHERE id = ra.registered_by));
