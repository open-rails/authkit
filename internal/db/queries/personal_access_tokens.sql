-- Personal tokens never share the organization API-key namespace.
-- name: PersonalTokenInsert :one
INSERT INTO personal_access_tokens(owner_user_id, permission_group_id, catalog_issuer, lookup_id, secret_hash, name, permissions, expires_at)
VALUES(sqlc.arg(owner_user_id), sqlc.arg(group_id), sqlc.arg(issuer), sqlc.arg(lookup_id), sqlc.arg(secret_hash), sqlc.arg(name), sqlc.arg(permissions)::text[], sqlc.arg(expires_at))
ON CONFLICT(lookup_id) DO NOTHING
RETURNING id, created_at;

-- name: PersonalTokensByOwner :many
SELECT id, owner_user_id, permission_group_id, name, permissions, created_at, last_used_at, expires_at, revoked_at
FROM personal_access_tokens
WHERE owner_user_id=sqlc.arg(owner_user_id) AND catalog_issuer=sqlc.arg(issuer)
 AND (sqlc.narg(after)::uuid IS NULL OR id<sqlc.narg(after)::uuid)
ORDER BY id DESC LIMIT sqlc.arg(page_limit)::bigint;

-- name: PersonalTokenByLookupID :one
SELECT p.id, p.owner_user_id, p.permission_group_id, p.permissions, p.secret_hash,
       u.tenant_id::text AS tenant_id, g.persona, g.created_at AS group_created_at
FROM personal_access_tokens p JOIN usable_users live ON live.id=p.owner_user_id
JOIN users u ON u.id=live.id
JOIN permission_groups g ON g.id=p.permission_group_id AND g.deleted_at IS NULL
WHERE p.lookup_id=sqlc.arg(lookup_id) AND p.catalog_issuer=sqlc.arg(issuer)
 AND p.revoked_at IS NULL AND p.expires_at>now();

-- name: PersonalTokenByID :one
SELECT p.id, p.owner_user_id, p.permission_group_id, p.permissions,
       u.tenant_id::text AS tenant_id, g.persona, g.created_at AS group_created_at
FROM personal_access_tokens p JOIN usable_users live ON live.id=p.owner_user_id
JOIN users u ON u.id=live.id
JOIN permission_groups g ON g.id=p.permission_group_id AND g.deleted_at IS NULL
WHERE p.id=sqlc.arg(id) AND p.catalog_issuer=sqlc.arg(issuer)
 AND p.revoked_at IS NULL AND p.expires_at>now();

-- name: PersonalTokenRevoke :exec
UPDATE personal_access_tokens SET revoked_at=coalesce(revoked_at,now())
WHERE id=sqlc.arg(id) AND owner_user_id=sqlc.arg(owner_user_id) AND catalog_issuer=sqlc.arg(issuer);

-- name: PersonalTokensRevokeOwnedBy :exec
UPDATE personal_access_tokens SET revoked_at=now()
WHERE owner_user_id=sqlc.arg(owner_user_id)::uuid AND revoked_at IS NULL;

-- name: PersonalTokenTouch :exec
UPDATE personal_access_tokens SET last_used_at=now()
WHERE id=sqlc.arg(id) AND (last_used_at IS NULL OR last_used_at<now()-interval '5 minutes');

-- name: PersonalTokensDeleteExpiredBatch :exec
WITH batch AS (
 SELECT id FROM personal_access_tokens WHERE LEAST(revoked_at,expires_at)<sqlc.arg(cutoff)::timestamptz
 ORDER BY LEAST(revoked_at,expires_at),id LIMIT sqlc.arg(batch_size)::bigint FOR UPDATE SKIP LOCKED)
DELETE FROM personal_access_tokens WHERE id IN(SELECT id FROM batch);
