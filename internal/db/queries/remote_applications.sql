-- Remote application registry (core/service_remote_applications.go). A
-- remote_application is the federation PRINCIPAL: it authenticates by signing
-- JWTs verified against its JWKS/public keys (#74).
--
-- #111: the controlling group column was renamed org_id -> permission_group_id.
-- The sqlc arg/output names stay `org_id` so the generated Go field is OrgID —
-- the authbase RemoteApplication.OrgID field is deliberately retained and now
-- carries the controlling permission_group_id.

-- name: RemoteApplicationUpsert :one
INSERT INTO profiles.remote_applications (slug, permission_group_id, issuer, jwks_uri, mode, public_keys, audiences, allowed_origins, enabled)
VALUES (sqlc.arg(slug), sqlc.narg(org_id)::uuid, sqlc.arg(issuer), sqlc.arg(jwks_uri), sqlc.arg(mode), sqlc.arg(public_keys), sqlc.arg(audiences), sqlc.arg(allowed_origins), sqlc.arg(enabled))
ON CONFLICT (issuer) DO UPDATE
  SET slug          = EXCLUDED.slug,
      permission_group_id = EXCLUDED.permission_group_id,
      jwks_uri      = EXCLUDED.jwks_uri,
      mode          = EXCLUDED.mode,
      public_keys   = EXCLUDED.public_keys,
      audiences     = EXCLUDED.audiences,
      allowed_origins = EXCLUDED.allowed_origins,
      enabled       = EXCLUDED.enabled,
      updated_at    = now()
RETURNING id::text, slug, COALESCE(permission_group_id::text, '')::text AS org_id, issuer, jwks_uri, mode, public_keys, audiences, allowed_origins, enabled, created_at, updated_at;

-- name: RemoteApplicationByIssuer :one
SELECT id::text, slug, COALESCE(permission_group_id::text, '')::text AS org_id, issuer, jwks_uri, mode, public_keys, audiences, allowed_origins, enabled, created_at, updated_at
FROM profiles.remote_applications
WHERE issuer = $1 AND deleted_at IS NULL;

-- name: RemoteApplicationBySlug :one
SELECT id::text, slug, COALESCE(permission_group_id::text, '')::text AS org_id, issuer, jwks_uri, mode, public_keys, audiences, allowed_origins, enabled, created_at, updated_at
FROM profiles.remote_applications
WHERE slug = $1 AND deleted_at IS NULL;

-- name: RemoteApplicationsAll :many
SELECT id::text, slug, COALESCE(permission_group_id::text, '')::text AS org_id, issuer, jwks_uri, mode, public_keys, audiences, allowed_origins, enabled, created_at, updated_at
FROM profiles.remote_applications
WHERE deleted_at IS NULL
ORDER BY slug ASC;

-- name: RemoteApplicationsEnabled :many
SELECT id::text, slug, COALESCE(permission_group_id::text, '')::text AS org_id, issuer, jwks_uri, mode, public_keys, audiences, allowed_origins, enabled, created_at, updated_at
FROM profiles.remote_applications
WHERE enabled = true AND deleted_at IS NULL
ORDER BY slug ASC;

-- name: RemoteApplicationDelete :execrows
DELETE FROM profiles.remote_applications WHERE issuer = $1;

-- Attribute definition registry (#75): REFERENCE-mode opaque definitions.

-- name: RemoteAppAttributeDefUpsert :one
INSERT INTO profiles.remote_application_attribute_defs (remote_application_id, key, version, definition)
VALUES (sqlc.arg(remote_application_id)::uuid, $2, $3, $4)
ON CONFLICT (remote_application_id, key, version) DO UPDATE
  SET definition = EXCLUDED.definition, updated_at = now()
RETURNING remote_application_id::text AS remote_application_id, key, version, definition, created_at, updated_at;

-- name: RemoteAppAttributeDefGet :one
SELECT remote_application_id::text AS remote_application_id, key, version, definition, created_at, updated_at
FROM profiles.remote_application_attribute_defs
WHERE remote_application_id = sqlc.arg(remote_application_id)::uuid AND key = $2 AND version = $3;

-- name: RemoteAppAttributeDefGetLatest :one
SELECT remote_application_id::text AS remote_application_id, key, version, definition, created_at, updated_at
FROM profiles.remote_application_attribute_defs
WHERE remote_application_id = sqlc.arg(remote_application_id)::uuid AND key = $2
ORDER BY version DESC
LIMIT 1;

-- name: RemoteAppAttributeDefsList :many
SELECT remote_application_id::text AS remote_application_id, key, version, definition, created_at, updated_at
FROM profiles.remote_application_attribute_defs
WHERE remote_application_id = sqlc.arg(remote_application_id)::uuid
ORDER BY key ASC, version DESC;

-- name: RemoteAppAttributeDefDelete :execrows
DELETE FROM profiles.remote_application_attribute_defs
WHERE remote_application_id = sqlc.arg(remote_application_id)::uuid AND key = $2;
