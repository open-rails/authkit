-- Remote application registry. A
-- remote_application is a registered application: it authenticates by signing
-- JWTs verified against its JWKS/public keys (#74).
--
-- The controlling group is addressed as permission_group_id throughout. Every
-- read returns the whole row: db.RemoteApplication.

-- name: RemoteApplicationUpsert :one
INSERT INTO remote_applications (permission_group_id, issuer, jwks_uri, mode, public_keys, enabled, catalog_issuer)
VALUES (sqlc.arg(permission_group_id)::uuid, sqlc.arg(issuer), sqlc.arg(jwks_uri), sqlc.arg(mode), sqlc.arg(public_keys), sqlc.arg(enabled), sqlc.arg(catalog_issuer)::text)
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
-- The registrar's app becomes the registration's.
UPDATE remote_applications SET registered_by = sqlc.arg(registered_by)::uuid, catalog_issuer = sqlc.arg(catalog_issuer)::text
WHERE id = sqlc.arg(id)::uuid;

-- name: RemoteApplicationsClearRegistrar :exec
UPDATE remote_applications SET registered_by = NULL, updated_at = now() WHERE registered_by = sqlc.arg(user_id)::uuid;

-- name: RemoteApplicationControlRoles :many
-- The roles an application holds in live groups.
SELECT g.id::text AS group_id, g.persona, r.role
FROM group_remote_application_roles r
JOIN permission_groups g ON g.id = r.permission_group_id
WHERE r.remote_application_id = sqlc.arg(remote_application_id)::uuid AND g.deleted_at IS NULL
ORDER BY g.id;

-- name: RemoteApplicationsDeclare :exec
-- declared_by declares these issuers in the group.
UPDATE remote_applications SET declared_by = sqlc.arg(declared_by)::text
WHERE permission_group_id = sqlc.arg(permission_group_id)::uuid
  AND issuer = ANY(sqlc.arg(issuers)::text[]) AND declared_by IS DISTINCT FROM sqlc.arg(declared_by)::text;

-- name: RemoteApplicationsUndeclared :many
-- What declared_by declared in the group before and no longer does.
SELECT * FROM remote_applications
WHERE declared_by = sqlc.arg(declared_by)::text AND permission_group_id = sqlc.arg(permission_group_id)::uuid
  AND NOT (issuer = ANY(sqlc.arg(issuers)::text[]))
ORDER BY issuer
FOR UPDATE;

-- name: RemoteApplicationsRelease :exec
-- Disables them and ends the declaration: a later registration is an
-- operation's.
UPDATE remote_applications SET enabled = false, declared_by = NULL, updated_at = now()
WHERE id = ANY(sqlc.arg(ids)::uuid[]);
