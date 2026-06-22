-- Owner-namespace queries (core/service_owner_namespace*.go, core/owner_namespace_lookup.go).
--
-- #111 hard cut: the org plane is gone, so the org-namespace probes (orgs /
-- org_renames) were dropped. Only the user/owner-reserved-name namespace queries
-- remain.

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

-- name: UserIsReserved :one
SELECT (CASE
  WHEN jsonb_typeof(COALESCE(metadata, '{}'::jsonb)->'reserved')='boolean'
  THEN (COALESCE(metadata, '{}'::jsonb)->>'reserved')::boolean
  ELSE false
END)::boolean AS reserved
FROM profiles.users
WHERE id = sqlc.arg(id)::uuid;

-- Slug-availability probes (core/service_owner_namespace.go ownerSlugAvailable).

-- name: OwnerSlugUserExists :one
SELECT EXISTS (
  SELECT 1
  FROM profiles.users u
  WHERE u.username = sqlc.arg(slug)::text::citext
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

-- name: NamespaceUserRenameBySlug :one
SELECT u.id::text AS id, u.username::text AS username, (u.deleted_at IS NOT NULL)::boolean AS deleted, r.renamed_at
FROM profiles.user_renames r
JOIN profiles.users u ON u.id = r.user_id
WHERE r.from_slug = $1
ORDER BY r.renamed_at DESC
LIMIT 1;
