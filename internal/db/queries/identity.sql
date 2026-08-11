-- Batch user projections (core user enrichment paths).

-- name: IdentityUsersByIDs :many
SELECT id, username, email
FROM profiles.users
WHERE id = ANY(sqlc.arg(ids)::uuid[]);

-- name: IdentityPublicUsersByIDs :many
-- The PUBLIC-safe display projection (#268): no email column is selected, so a
-- caller cannot leak one by forgetting a tag. Soft-deleted rows ARE returned —
-- the Go layer tombstones them — so a reference to a deleted author resolves to
-- a stable placeholder instead of silently vanishing.
SELECT id, username, avatar_url, biography, created_at, deleted_at
FROM profiles.users
WHERE id = ANY(sqlc.arg(ids)::uuid[]);

-- name: IdentityUserLivenessByIDs :many
-- The batch account-liveness read behind verify's liveness gate (#267): the ban/
-- delete/reserve columns AND the fresh identity fields, in ONE query, so a host
-- never needs an admin-privileged user read to refresh display claims. The
-- reserved expression mirrors UserIsReserved (owner_namespace.sql) so the two
-- cannot disagree about what "reserved" means.
SELECT id, username, email, email_verified, avatar_url,
       banned_at, banned_until, ban_reason, banned_by, deleted_at,
       (CASE
          WHEN jsonb_typeof(COALESCE(metadata, '{}'::jsonb)->'reserved')='boolean'
          THEN (COALESCE(metadata, '{}'::jsonb)->>'reserved')::boolean
          ELSE false
        END)::boolean AS reserved
FROM profiles.users
WHERE id = ANY(sqlc.arg(ids)::uuid[]);
