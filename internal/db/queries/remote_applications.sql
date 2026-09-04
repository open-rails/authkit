-- Remote application registry (core/service_remote_applications.go). A
-- remote_application is the federation PRINCIPAL: it authenticates by signing
-- JWTs verified against its JWKS/public keys (#74).
--
-- The controlling group is addressed as permission_group_id throughout.

-- name: RemoteApplicationUpsert :one
INSERT INTO profiles.remote_applications (slug, permission_group_id, issuer, jwks_uri, mode, public_keys, enabled)
VALUES (sqlc.arg(slug), sqlc.narg(permission_group_id)::uuid, sqlc.arg(issuer), sqlc.arg(jwks_uri), sqlc.arg(mode), sqlc.arg(public_keys), sqlc.arg(enabled))
ON CONFLICT (issuer) DO UPDATE
  SET slug          = EXCLUDED.slug,
      jwks_uri      = EXCLUDED.jwks_uri,
      mode          = EXCLUDED.mode,
      public_keys   = EXCLUDED.public_keys,
      enabled       = EXCLUDED.enabled,
      updated_at    = now()
WHERE remote_applications.permission_group_id = EXCLUDED.permission_group_id
RETURNING id::text, slug, COALESCE(permission_group_id::text, '')::text AS permission_group_id, issuer, jwks_uri, mode, public_keys, enabled, display_name, tier, trust_root, domain, document_endpoint, root_verified_at, created_at, updated_at;

-- name: RemoteApplicationByIssuer :one
SELECT id::text, slug, COALESCE(permission_group_id::text, '')::text AS permission_group_id, issuer, jwks_uri, mode, public_keys, enabled, display_name, tier, trust_root, domain, document_endpoint, root_verified_at, created_at, updated_at
FROM profiles.remote_applications
WHERE issuer = $1;

-- name: RemoteApplicationBySlug :one
SELECT id::text, slug, COALESCE(permission_group_id::text, '')::text AS permission_group_id, issuer, jwks_uri, mode, public_keys, enabled, display_name, tier, trust_root, domain, document_endpoint, root_verified_at, created_at, updated_at
FROM profiles.remote_applications
WHERE slug = $1;

-- name: RemoteApplicationsAll :many
SELECT id::text, slug, COALESCE(permission_group_id::text, '')::text AS permission_group_id, issuer, jwks_uri, mode, public_keys, enabled, display_name, tier, trust_root, domain, document_endpoint, root_verified_at, created_at, updated_at
FROM profiles.remote_applications
ORDER BY slug ASC;

-- name: RemoteApplicationsEnabled :many
SELECT id::text, slug, COALESCE(permission_group_id::text, '')::text AS permission_group_id, issuer, jwks_uri, mode, public_keys, enabled, display_name, tier, trust_root, domain, document_endpoint, root_verified_at, created_at, updated_at
FROM profiles.remote_applications
WHERE enabled = true
ORDER BY slug ASC;

-- name: RemoteApplicationDelete :execrows
DELETE FROM profiles.remote_applications WHERE issuer = $1;

-- Application self-registration (#264). Domain-rooted rows are KEYED by the
-- proven domain (create-or-reprove idempotency); the slug is a separately
-- claimed handle and the uuid stays stable across every refresh/rotation.

-- name: RemoteApplicationBySlugForUpdate :one
SELECT id::text, slug, COALESCE(permission_group_id::text, '')::text AS permission_group_id, issuer, jwks_uri, mode, public_keys, enabled, display_name, tier, trust_root, domain, document_endpoint, root_verified_at, created_at, updated_at
FROM profiles.remote_applications
WHERE slug = $1
FOR UPDATE;

-- name: RemoteApplicationByDomainForUpdate :one
SELECT id::text, slug, COALESCE(permission_group_id::text, '')::text AS permission_group_id, issuer, jwks_uri, mode, public_keys, enabled, display_name, tier, trust_root, domain, document_endpoint, root_verified_at, created_at, updated_at
FROM profiles.remote_applications
WHERE domain = $1
FOR UPDATE;

-- name: RemoteApplicationDomainInsert :one
INSERT INTO profiles.remote_applications (slug, permission_group_id, issuer, jwks_uri, mode, public_keys, enabled, display_name, tier, trust_root, domain, document_endpoint, root_verified_at)
VALUES (sqlc.arg(slug), sqlc.narg(permission_group_id)::uuid, sqlc.arg(issuer), sqlc.arg(jwks_uri), sqlc.arg(mode), sqlc.arg(public_keys), true, sqlc.arg(display_name), 'registered', 'domain', sqlc.arg(domain), sqlc.arg(document_endpoint), now())
RETURNING id::text, slug, COALESCE(permission_group_id::text, '')::text AS permission_group_id, issuer, jwks_uri, mode, public_keys, enabled, display_name, tier, trust_root, domain, document_endpoint, root_verified_at, created_at, updated_at;

-- name: RemoteApplicationDomainRefresh :one
-- Idempotent re-registration: the re-fetched document is the trust-root proof,
-- so it refreshes issuer/keys/config, re-proves the root, and re-enables a
-- sweeper-disabled row. Tier is untouched (approval is an admin act).
UPDATE profiles.remote_applications
SET issuer            = sqlc.arg(issuer),
    jwks_uri          = sqlc.arg(jwks_uri),
    mode              = sqlc.arg(mode),
    public_keys       = sqlc.arg(public_keys),
    display_name      = sqlc.arg(display_name),
    document_endpoint = sqlc.arg(document_endpoint),
    enabled           = true,
    root_verified_at  = now(),
    updated_at        = now()
WHERE domain = sqlc.arg(domain) AND trust_root = 'domain'
RETURNING id::text, slug, COALESCE(permission_group_id::text, '')::text AS permission_group_id, issuer, jwks_uri, mode, public_keys, enabled, display_name, tier, trust_root, domain, document_endpoint, root_verified_at, created_at, updated_at;

-- name: RemoteApplicationRepoint :one
-- Application.json re-point: the app moved domains (the TRUST ROOT moves).
-- Signed request + a fresh fetch of the NEW domain's document both verified
-- by the caller. uuid, slug, and org are all stable — the slug is a claimed
-- handle, not the domain.
UPDATE profiles.remote_applications
SET domain            = sqlc.arg(new_domain),
    issuer            = sqlc.arg(issuer),
    jwks_uri          = sqlc.arg(jwks_uri),
    mode              = sqlc.arg(mode),
    public_keys       = sqlc.arg(public_keys),
    display_name      = sqlc.arg(display_name),
    document_endpoint = sqlc.arg(document_endpoint),
    enabled           = true,
    root_verified_at  = now(),
    updated_at        = now()
WHERE slug = sqlc.arg(slug) AND trust_root = 'domain'
RETURNING id::text, slug, COALESCE(permission_group_id::text, '')::text AS permission_group_id, issuer, jwks_uri, mode, public_keys, enabled, display_name, tier, trust_root, domain, document_endpoint, root_verified_at, created_at, updated_at;

-- name: RemoteApplicationRotateTrustSource :one
-- Old-key-signs-new convenience rotation (the trust root remains the ONLY
-- mandatory rotation path). Does NOT touch root_verified_at.
UPDATE profiles.remote_applications
SET jwks_uri    = sqlc.arg(jwks_uri),
    mode        = sqlc.arg(mode),
    public_keys = sqlc.arg(public_keys),
    updated_at  = now()
WHERE slug = sqlc.arg(slug)
RETURNING id::text, slug, COALESCE(permission_group_id::text, '')::text AS permission_group_id, issuer, jwks_uri, mode, public_keys, enabled, display_name, tier, trust_root, domain, document_endpoint, root_verified_at, created_at, updated_at;

-- name: RemoteApplicationSetTier :one
UPDATE profiles.remote_applications
SET tier = sqlc.arg(tier), updated_at = now()
WHERE slug = sqlc.arg(slug)
RETURNING id::text, slug, COALESCE(permission_group_id::text, '')::text AS permission_group_id, issuer, jwks_uri, mode, public_keys, enabled, display_name, tier, trust_root, domain, document_endpoint, root_verified_at, created_at, updated_at;

-- name: RemoteApplicationSetEnabled :one
-- Host-sweeper primitive (#264 ruling 5: re-verification cadence is host
-- policy). Re-registration (fresh domain proof) also re-enables.
UPDATE profiles.remote_applications
SET enabled = sqlc.arg(enabled), updated_at = now()
WHERE slug = sqlc.arg(slug)
RETURNING id::text, slug, COALESCE(permission_group_id::text, '')::text AS permission_group_id, issuer, jwks_uri, mode, public_keys, enabled, display_name, tier, trust_root, domain, document_endpoint, root_verified_at, created_at, updated_at;

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
