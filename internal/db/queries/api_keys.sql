-- API key queries.

-- name: APIKeysRevokeCreatedBy :exec
UPDATE api_keys SET revoked_at = now() WHERE created_by = sqlc.arg(user_id)::uuid AND revoked_at IS NULL;

-- name: APIKeyInsert :one
INSERT INTO api_keys (permission_group_id, key_id, secret_hash, name, role, created_by, expires_at)
VALUES (sqlc.arg(group_id), sqlc.arg(key_id), sqlc.arg(secret_hash), sqlc.arg(name), sqlc.arg(role), sqlc.narg(created_by)::uuid, sqlc.narg(expires_at)::timestamptz)
ON CONFLICT (key_id) DO NOTHING
RETURNING id, created_at;

-- APIKeysByGroup lists a group's keys newest first, never the secret hash.
-- name: APIKeysByGroup :many
SELECT id, key_id, name, role, COALESCE(created_by::text, '')::text AS created_by, created_at, last_used_at, expires_at, revoked_at
FROM api_keys
WHERE permission_group_id = sqlc.arg(group_id) AND (sqlc.narg(after)::uuid IS NULL OR id < sqlc.narg(after)::uuid)
ORDER BY id DESC
LIMIT sqlc.arg(page_limit)::bigint;

-- name: APIKeyRoleForUpdate :one
SELECT role FROM api_keys WHERE id = sqlc.arg(id) AND permission_group_id = sqlc.arg(group_id) AND revoked_at IS NULL FOR UPDATE;

-- name: APIKeyRevoke :exec
UPDATE api_keys SET revoked_at = now() WHERE id = sqlc.arg(id);

-- APIKeyByLookupID reads a key of a live group. creator_live: the key's
-- creator is the system (NULL) or a usable account.
-- name: APIKeyByLookupID :one
SELECT k.id, k.secret_hash, k.role, k.expires_at, k.revoked_at,
  (k.created_by IS NULL OR EXISTS(SELECT 1 FROM usable_users WHERE id = k.created_by))::boolean AS creator_live,
  g.id AS group_id, g.persona, g.created_at AS group_created_at
FROM api_keys k JOIN permission_groups g ON g.id = k.permission_group_id
WHERE k.key_id = sqlc.arg(key_id) AND g.deleted_at IS NULL;

-- APIKeyTouch records a use at most once per 5 minutes per key.
-- name: APIKeyTouch :exec
UPDATE api_keys SET last_used_at = now()
WHERE id = sqlc.arg(id) AND (last_used_at IS NULL OR last_used_at < now() - interval '5 minutes');

-- name: APIKeyRoleCounts :many
SELECT pg.persona, r.role, count(*)::bigint AS n
FROM api_keys r JOIN permission_groups pg ON pg.id = r.permission_group_id
WHERE r.revoked_at IS NULL
GROUP BY pg.persona, r.role;
