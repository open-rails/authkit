-- Remote application registry. A
-- remote_application is the federation PRINCIPAL: it authenticates by signing
-- JWTs verified against its JWKS/public keys (#74).
--
-- The controlling group is addressed as permission_group_id throughout.

-- name: RemoteApplicationUpsert :one
INSERT INTO remote_applications (slug, permission_group_id, issuer, jwks_uri, mode, public_keys, enabled)
VALUES (sqlc.arg(slug), sqlc.narg(permission_group_id)::uuid, sqlc.arg(issuer), sqlc.arg(jwks_uri), sqlc.arg(mode), sqlc.arg(public_keys), sqlc.arg(enabled))
ON CONFLICT (issuer) DO UPDATE
  SET slug          = EXCLUDED.slug,
      jwks_uri      = EXCLUDED.jwks_uri,
      mode          = EXCLUDED.mode,
      public_keys   = EXCLUDED.public_keys,
      enabled       = EXCLUDED.enabled,
      updated_at    = now()
WHERE remote_applications.permission_group_id = EXCLUDED.permission_group_id
RETURNING id::text, slug, COALESCE(permission_group_id::text, '')::text AS permission_group_id, issuer, jwks_uri, mode, public_keys, enabled, trust_root, created_at, updated_at;

-- name: RemoteApplicationByIssuer :one
SELECT id::text, slug, COALESCE(permission_group_id::text, '')::text AS permission_group_id, issuer, jwks_uri, mode, public_keys, enabled, trust_root, created_at, updated_at
FROM remote_applications
WHERE issuer = $1;

-- name: RemoteApplicationsEnabled :many
SELECT id::text, slug, COALESCE(permission_group_id::text, '')::text AS permission_group_id, issuer, jwks_uri, mode, public_keys, enabled, trust_root, created_at, updated_at
FROM remote_applications
WHERE enabled = true
ORDER BY slug ASC;

-- name: RemoteApplicationDelete :execrows
DELETE FROM remote_applications WHERE issuer = $1;

-- name: RemoteApplicationBySlugForUpdate :one
SELECT id::text, slug, COALESCE(permission_group_id::text, '')::text AS permission_group_id, issuer, jwks_uri, mode, public_keys, enabled, trust_root, created_at, updated_at
FROM remote_applications
WHERE slug = $1
FOR UPDATE;
