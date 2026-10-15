-- The SCIM service provider's reads (GET /scim/v2/Users). An address
-- matches only once verified: a SCIM User shows no other.

-- name: SCIMUsersMatching :many
SELECT * FROM users
WHERE tenant_id=NULLIF(sqlc.arg(tenant_id)::text,'')::uuid AND (id = ANY(sqlc.arg(ids)::uuid[])
   OR username = ANY(sqlc.arg(usernames)::text[]::public.citext[])
   OR (email_verified AND email = ANY(sqlc.arg(emails)::text[]::public.citext[])))
ORDER BY id;

-- name: SCIMUsersPage :many
SELECT * FROM users WHERE tenant_id=NULLIF(sqlc.arg(tenant_id)::text,'')::uuid ORDER BY id LIMIT sqlc.arg(page_size) OFFSET sqlc.arg(skip);

-- name: SCIMUsersCount :one
SELECT count(*)::bigint FROM users WHERE tenant_id=NULLIF(sqlc.arg(tenant_id)::text,'')::uuid;

-- name: UserInfoSearch :many
-- Live accounts whose username or verified email contains the pattern, in
-- any case (pg_trgm GIN on the columns as text, migration 0002).
SELECT * FROM users u
WHERE u.tenant_id=NULLIF(sqlc.arg(tenant_id)::text,'')::uuid AND u.deleted_at IS NULL
  AND (u.username::text ILIKE sqlc.arg(pattern)::text
       OR (u.email_verified AND u.email::text ILIKE sqlc.arg(pattern)::text))
ORDER BY u.id
LIMIT sqlc.arg(max_rows);
