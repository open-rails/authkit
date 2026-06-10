-- Owner-namespace queries (core/service_owner_namespace*.go, core/owner_namespace_lookup.go).

-- name: OwnerReservedNameExists :one
SELECT EXISTS(
  SELECT 1 FROM profiles.owner_reserved_names WHERE slug = $1
);

-- name: OwnerReservedNameUpsert :exec
INSERT INTO profiles.owner_reserved_names (slug)
VALUES ($1)
ON CONFLICT (slug) DO UPDATE SET updated_at = now();

-- name: OwnerReservedNameDelete :execrows
DELETE FROM profiles.owner_reserved_names WHERE slug = $1;

-- Recent rename history blocks reuse without a separate hold table. Joins to
-- owner rows without filtering soft deletes: soft deletion keeps the namespace
-- held, while hard deletion removes/cascades the owner row and allows
-- eventual reuse.
-- name: OwnerSlugConflictExists :one
SELECT (
  EXISTS(SELECT 1 FROM profiles.users u WHERE u.username = sqlc.arg(slug)::text)
  OR EXISTS(
    SELECT 1 FROM profiles.user_renames r
    JOIN profiles.users u ON u.id = r.user_id
    WHERE r.from_slug = sqlc.arg(slug)::text AND r.renamed_at >= sqlc.arg(reuse_cutoff)::timestamptz
  )
  OR EXISTS(SELECT 1 FROM profiles.tenants o WHERE o.slug = sqlc.arg(slug)::text)
  OR EXISTS(
    SELECT 1 FROM profiles.tenant_renames r
    JOIN profiles.tenants o ON o.id = r.tenant_id
    WHERE r.from_slug = sqlc.arg(slug)::text AND r.renamed_at >= sqlc.arg(reuse_cutoff)::timestamptz
  )
)::boolean AS conflict_exists;

-- name: UserIsReserved :one
SELECT (CASE
  WHEN jsonb_typeof(COALESCE(metadata, '{}'::jsonb)->'reserved')='boolean'
  THEN (COALESCE(metadata, '{}'::jsonb)->>'reserved')::boolean
  ELSE false
END)::boolean AS reserved
FROM profiles.users
WHERE id = sqlc.arg(id)::uuid;

-- name: TenantNamespaceStateByID :one
SELECT COALESCE(COALESCE(metadata, '{}'::jsonb)->>'namespace_state', '')::text AS state_raw,
       (CASE
         WHEN jsonb_typeof(COALESCE(metadata, '{}'::jsonb)->'reserved')='boolean'
         THEN (COALESCE(metadata, '{}'::jsonb)->>'reserved')::boolean
         ELSE false
       END)::boolean AS reserved
FROM profiles.tenants
WHERE id = sqlc.arg(id)::uuid AND deleted_at IS NULL;

-- name: TenantSetNamespaceState :execrows
UPDATE profiles.tenants
SET metadata = jsonb_set(
      jsonb_set(COALESCE(metadata, '{}'::jsonb), '{namespace_state}', to_jsonb(sqlc.arg(state)::text), true),
      '{reserved}', to_jsonb(sqlc.arg(reserved)::boolean), true
    ),
    updated_at = now()
WHERE id = sqlc.arg(id)::uuid AND deleted_at IS NULL;

-- name: TenantIDPersonalBySlug :one
SELECT id::text, is_personal
FROM profiles.tenants
WHERE slug = $1 AND deleted_at IS NULL;

-- name: TenantInsertWithState :one
INSERT INTO profiles.tenants (id, slug, metadata)
VALUES (sqlc.arg(id)::uuid, $2, jsonb_build_object('namespace_state', sqlc.arg(state)::text, 'reserved', to_jsonb(true)))
RETURNING id::text;

-- Slug-availability probes (core/service_owner_namespace.go ownerSlugAvailable).

-- name: OwnerSlugUserExists :one
SELECT EXISTS (
  SELECT 1
  FROM profiles.users u
  WHERE u.username = sqlc.arg(slug)::text
    AND (sqlc.arg(exclude_user_id)::text = '' OR u.id::text <> sqlc.arg(exclude_user_id)::text)
);

-- name: OwnerSlugUserRenameHeld :one
SELECT EXISTS (
  SELECT 1
  FROM profiles.user_renames r
  JOIN profiles.users u ON u.id = r.user_id
  WHERE r.from_slug = sqlc.arg(slug)::text
    AND r.renamed_at >= sqlc.arg(reuse_cutoff)::timestamptz
    AND (sqlc.arg(exclude_user_id)::text = '' OR r.user_id::text <> sqlc.arg(exclude_user_id)::text)
);

-- name: OwnerSlugTenantExists :one
SELECT EXISTS (
  SELECT 1
  FROM profiles.tenants o
  WHERE o.slug = sqlc.arg(slug)::text
    AND (sqlc.arg(exclude_tenant_id)::text = '' OR o.id::text <> sqlc.arg(exclude_tenant_id)::text)
);

-- name: OwnerSlugTenantRenameHeld :one
SELECT EXISTS (
  SELECT 1
  FROM profiles.tenant_renames r
  JOIN profiles.tenants o ON o.id = r.tenant_id
  WHERE r.from_slug = sqlc.arg(slug)::text
    AND r.renamed_at >= sqlc.arg(reuse_cutoff)::timestamptz
    AND (sqlc.arg(exclude_tenant_id)::text = '' OR r.tenant_id::text <> sqlc.arg(exclude_tenant_id)::text)
);

-- name: PersonalTenantByOwner :one
SELECT id::text, slug, is_personal, COALESCE(owner_user_id::text, '')::text AS owner_user_id
FROM profiles.tenants
WHERE owner_user_id = sqlc.arg(owner_user_id)::uuid AND is_personal = true AND deleted_at IS NULL;

-- name: UserSlugAliases :many
SELECT DISTINCT from_slug
FROM profiles.user_renames
WHERE user_id = sqlc.arg(user_id)::uuid
ORDER BY from_slug ASC;

-- name: UserBySlug :one
SELECT id::text, username::text
FROM profiles.users
WHERE username = $1 AND deleted_at IS NULL;

-- Fallback to renames table (issue #58). Most-recent rename wins when a slug
-- has been used by multiple users at different times (only possible after
-- hard-delete + reuse).
-- name: UserBySlugViaRename :one
SELECT u.id::text AS id, u.username::text AS username
FROM profiles.user_renames r
JOIN profiles.users u ON u.id = r.user_id AND u.deleted_at IS NULL
WHERE r.from_slug = $1
ORDER BY r.renamed_at DESC
LIMIT 1;

-- name: TenantAliases :many
SELECT DISTINCT from_slug
FROM profiles.tenant_renames
WHERE tenant_id = sqlc.arg(tenant_id)::uuid
ORDER BY from_slug ASC;

-- name: PersonalTenantUpsert :one
INSERT INTO profiles.tenants (id, slug, is_personal, owner_user_id, metadata)
VALUES (sqlc.arg(id)::uuid, $2, true, sqlc.arg(owner_user_id)::uuid, jsonb_build_object('namespace_state', 'registered_tenant', 'reserved', to_jsonb(false)))
ON CONFLICT (owner_user_id) WHERE is_personal = true AND deleted_at IS NULL
DO UPDATE SET slug = EXCLUDED.slug, updated_at = now()
RETURNING id::text;

-- Namespace lookup probes (core/owner_namespace_lookup.go). These read soft-
-- deleted rows on purpose (deleted_at IS NOT NULL surfaces as a flag).

-- name: NamespaceUserBySlug :one
SELECT id::text,
       username::text,
       (deleted_at IS NOT NULL)::boolean AS deleted,
       (CASE
         WHEN jsonb_typeof(COALESCE(metadata, '{}'::jsonb)->'reserved')='boolean'
         THEN (COALESCE(metadata, '{}'::jsonb)->>'reserved')::boolean
         ELSE false
       END)::boolean AS reserved
FROM profiles.users
WHERE username = $1;

-- name: NamespaceTenantBySlug :one
SELECT id::text,
       slug,
       is_personal,
       COALESCE(owner_user_id::text, '')::text AS owner_user_id,
       (deleted_at IS NOT NULL)::boolean AS deleted,
       COALESCE(COALESCE(metadata, '{}'::jsonb)->>'namespace_state', '')::text AS state_raw,
       (CASE
         WHEN jsonb_typeof(COALESCE(metadata, '{}'::jsonb)->'reserved')='boolean'
         THEN (COALESCE(metadata, '{}'::jsonb)->>'reserved')::boolean
         ELSE false
       END)::boolean AS reserved
FROM profiles.tenants
WHERE slug = $1;

-- name: NamespaceUserRenameBySlug :one
SELECT u.id::text AS id, u.username::text AS username, (u.deleted_at IS NOT NULL)::boolean AS deleted, r.renamed_at
FROM profiles.user_renames r
JOIN profiles.users u ON u.id = r.user_id
WHERE r.from_slug = $1
ORDER BY r.renamed_at DESC
LIMIT 1;

-- name: NamespaceTenantRenameBySlug :one
SELECT o.id::text AS id, o.slug, o.is_personal, COALESCE(o.owner_user_id::text, '')::text AS owner_user_id, (o.deleted_at IS NOT NULL)::boolean AS deleted, r.renamed_at
FROM profiles.tenant_renames r
JOIN profiles.tenants o ON o.id = r.tenant_id
WHERE r.from_slug = $1
ORDER BY r.renamed_at DESC
LIMIT 1;
