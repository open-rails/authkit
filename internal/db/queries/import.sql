-- ImportUsers: bulk account import, one chunk per transaction.

-- name: ImportReleaseAliases :exec
-- Expired aliases of the chunk's names neither match nor block.
DELETE FROM name_claims
WHERE name = ANY(sqlc.arg(names)::text[])
  AND NOT canonical AND expires_at <= sqlc.arg(now)::timestamptz;

-- The ImportHits* reads share one row shape: the matched key, the account,
-- and whether it is deleted, the key verified on it, or a name reserved for
-- a purged account.

-- name: ImportHitsByID :many
SELECT id::text AS key, id::text AS user_id, (deleted_at IS NOT NULL)::boolean AS deleted,
       true AS verified, false AS missing
FROM users WHERE id = ANY(sqlc.arg(ids)::uuid[]);

-- name: ImportHitsByEmail :many
SELECT lower(email::text)::text AS key, id::text AS user_id, (deleted_at IS NOT NULL)::boolean AS deleted,
       email_verified AS verified, false AS missing
FROM users WHERE email = ANY(sqlc.arg(emails)::text[]::public.citext[]);

-- name: ImportHitsByPhone :many
SELECT COALESCE(phone_number, '')::text AS key, id::text AS user_id, (deleted_at IS NOT NULL)::boolean AS deleted,
       phone_verified AS verified, false AS missing
FROM users WHERE phone_number = ANY(sqlc.arg(phones)::text[]);

-- name: ImportHitsByName :many
-- A canonical name or a live alias.
SELECT c.name AS key, c.owner_id::text AS user_id, COALESCE(u.deleted_at IS NOT NULL, false)::boolean AS deleted,
       false AS verified, (u.id IS NULL)::boolean AS missing
FROM name_claims c LEFT JOIN users u ON u.id = c.owner_id
WHERE c.name = ANY(sqlc.arg(names)::text[])
  AND (c.canonical OR c.expires_at IS NULL OR c.expires_at > sqlc.arg(now)::timestamptz);

-- name: ImportMergeUser :exec
UPDATE users SET
  metadata = COALESCE(metadata, '{}'::jsonb) || sqlc.arg(metadata)::jsonb,
  created_at = LEAST(created_at, sqlc.arg(created_at)),
  last_login = GREATEST(last_login, sqlc.narg(last_login)),
  preferred_language = COALESCE(preferred_language, sqlc.narg(preferred_language)),
  avatar_url = COALESCE(avatar_url, sqlc.narg(avatar_url)),
  updated_at = now()
WHERE id = sqlc.arg(id)::uuid;

-- name: ImportMergePassword :exec
INSERT INTO user_passwords (user_id, password_hash, hash_algo)
VALUES (sqlc.arg(user_id)::uuid, sqlc.arg(password_hash), sqlc.arg(hash_algo))
ON CONFLICT (user_id) DO NOTHING;

-- name: ImportInsertUsers :many
-- users is a JSON array of users rows (column-named keys; a missing key is
-- NULL). A row losing a uniqueness race to another writer is not returned.
INSERT INTO users (id, email, phone_number, username, email_verified, phone_verified, banned_at, banned_until,
                   ban_reason, metadata, created_at, updated_at, last_login, preferred_language, avatar_url, deleted_at)
SELECT r.id, r.email, r.phone_number, r.username, r.email_verified, r.phone_verified, r.banned_at, r.banned_until,
       r.ban_reason, r.metadata, r.created_at, r.updated_at, r.last_login, r.preferred_language, r.avatar_url, r.deleted_at
FROM jsonb_populate_recordset(NULL::users, sqlc.arg(users)::jsonb) AS r
ON CONFLICT DO NOTHING
RETURNING id::text;

-- name: ImportInsertPasswords :exec
INSERT INTO user_passwords (user_id, password_hash, hash_algo)
SELECT k.user_id, k.password_hash, k.hash_algo
FROM unnest(sqlc.arg(user_ids)::uuid[], sqlc.arg(password_hashes)::text[], sqlc.arg(hash_algos)::text[])
  AS k(user_id, password_hash, hash_algo)
ON CONFLICT (user_id) DO NOTHING;

-- name: ImportHeldProviders :many
-- The identities some account holds, verified or not.
SELECT p.issuer, p.subject FROM user_providers p
JOIN unnest(sqlc.arg(issuers)::text[], sqlc.arg(subjects)::text[]) AS k(issuer, subject)
  ON p.issuer = k.issuer AND p.subject = k.subject;

-- name: ImportInsertProviders :execrows
-- An empty provider slug or provider email is stored as NULL.
INSERT INTO user_providers (user_id, issuer, provider_slug, subject, email_at_provider)
SELECT k.user_id, k.issuer, NULLIF(k.provider_slug, ''), k.subject, NULLIF(k.email_at_provider, '')
FROM unnest(sqlc.arg(user_ids)::uuid[], sqlc.arg(issuers)::text[], sqlc.arg(provider_slugs)::text[],
            sqlc.arg(subjects)::text[], sqlc.arg(emails_at_provider)::text[])
  AS k(user_id, issuer, provider_slug, subject, email_at_provider)
ON CONFLICT DO NOTHING;

-- name: ImportSetBannedBy :exec
-- Records who banned imported accounts; a banner that is no account leaves
-- banned_by NULL.
UPDATE users u SET banned_by = k.banned_by
FROM unnest(sqlc.arg(user_ids)::uuid[], sqlc.arg(banned_by)::uuid[]) AS k(user_id, banned_by)
WHERE u.id = k.user_id AND u.banned_at IS NOT NULL AND u.banned_by IS NULL
  AND EXISTS(SELECT 1 FROM users b WHERE b.id = k.banned_by);
