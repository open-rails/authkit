-- User-row queries (core/service.go).

-- name: UserByID :one
-- preferred_language is included in this projection (a widening; no existing
-- caller breaks) so callers that already load the user row — e.g. GET /me — read
-- the language off this row instead of issuing a separate UserPreferredLanguage
-- query (#228).
SELECT id, email, phone_number, username, email_verified, phone_verified, banned_at, banned_until, ban_reason, banned_by, deleted_at, created_at, updated_at, last_login, preferred_language, avatar_url
FROM users WHERE id = $1;

-- name: UserByEmail :one
SELECT id, email, phone_number, username, email_verified, phone_verified, banned_at, banned_until, ban_reason, banned_by, deleted_at, created_at, updated_at, last_login
FROM users WHERE email = lower(sqlc.arg(email)::text)::public.citext;

-- name: UserByPhone :one
SELECT id, email, phone_number, username, email_verified, phone_verified, banned_at, banned_until, ban_reason, banned_by, deleted_at, created_at, updated_at, last_login
FROM users WHERE phone_number = $1;

-- name: UserSetPhoneVerifiedByID :exec
UPDATE users SET phone_verified = $2, updated_at = NOW() WHERE id = $1;

-- name: UserSetPhoneVerifiedByIDAndPhone :exec
UPDATE users
SET phone_verified = true
WHERE id = $1 AND phone_number = $2;

-- name: UserEmailOrUsernameTaken :one
SELECT
  EXISTS(SELECT 1 FROM users WHERE email = lower(sqlc.arg(email)::text)::public.citext)::boolean AS email_taken,
  EXISTS(SELECT 1 FROM name_claims WHERE owner_kind='user' AND persona='' AND name=lower(sqlc.arg(username)::text) AND (canonical OR expires_at IS NULL OR expires_at>sqlc.arg(at_time)::timestamptz))::boolean AS username_taken;

-- name: UserPhoneOrUsernameTaken :one
SELECT
  EXISTS(SELECT 1 FROM users WHERE phone_number = sqlc.arg(phone)::text)::boolean AS phone_taken,
  EXISTS(SELECT 1 FROM name_claims WHERE owner_kind='user' AND persona='' AND name=lower(sqlc.arg(username)::text) AND (canonical OR expires_at IS NULL OR expires_at>sqlc.arg(at_time)::timestamptz))::boolean AS username_taken;

-- name: UserSetPreferredLanguage :exec
UPDATE users
SET preferred_language = $2,
    updated_at = now()
WHERE id = sqlc.arg(id)::uuid;

-- name: UserPreferredLanguage :one
SELECT COALESCE(preferred_language, '')::text AS language
FROM users
WHERE id = sqlc.arg(id)::uuid;

-- name: UserInsert :one
WITH claim AS MATERIALIZED (
 SELECT claim_canonical_name('user','',sqlc.arg(username)::text,sqlc.arg(id)::uuid,sqlc.arg(at_time)::timestamptz)
)
INSERT INTO users (id, email, username)
SELECT sqlc.arg(id)::uuid, NULLIF(lower(sqlc.arg(email)::text), ''), sqlc.arg(username) FROM claim
RETURNING id, email, username, email_verified, banned_at, deleted_at;

-- name: UserImportInsert :exec
WITH claim AS MATERIALIZED (
 SELECT claim_canonical_name('user','',sqlc.arg(username)::text,sqlc.arg(id)::uuid,sqlc.arg(at_time)::timestamptz)
)
INSERT INTO users (
  id, email, phone_number, username, email_verified, phone_verified,
  banned_at, banned_until, ban_reason, banned_by, metadata, created_at, updated_at
)
SELECT
  sqlc.arg(id)::uuid, sqlc.narg(email), sqlc.narg(phone_number), sqlc.arg(username), sqlc.arg(email_verified), sqlc.arg(phone_verified),
  sqlc.narg(banned_at), sqlc.narg(banned_until), sqlc.narg(ban_reason), sqlc.narg(banned_by)::uuid, sqlc.arg(metadata)::jsonb, sqlc.arg(created_at), sqlc.arg(updated_at)
FROM claim;

-- name: UserImportUpdate :one
UPDATE users
SET email = COALESCE(sqlc.narg(email), email),
    phone_number = COALESCE(sqlc.narg(phone_number), phone_number),
    username = sqlc.arg(username),
    email_verified = sqlc.arg(email_verified),
    phone_verified = sqlc.arg(phone_verified),
    banned_at = sqlc.narg(banned_at),
    banned_until = sqlc.narg(banned_until),
    ban_reason = sqlc.narg(ban_reason),
    banned_by = sqlc.narg(banned_by)::uuid,
    metadata = COALESCE(metadata, '{}'::jsonb) || sqlc.arg(metadata)::jsonb,
    created_at = CASE WHEN sqlc.arg(created_at) < created_at THEN sqlc.arg(created_at) ELSE created_at END,
    updated_at = sqlc.arg(updated_at)
WHERE id = sqlc.arg(id)::uuid
RETURNING id::text;

-- name: UserSetEmailVerified :exec
UPDATE users SET email_verified = $2, updated_at = NOW() WHERE id = $1;

-- name: UserPasswordInsert :exec
INSERT INTO user_passwords (user_id, password_hash, hash_algo)
VALUES ($1, $2, 'argon2id');

-- name: UserSetPhoneAndVerified :exec
UPDATE users
SET phone_number = $2, phone_verified = $3, updated_at = NOW()
WHERE id = $1;

-- name: UserSetLastLogin :exec
UPDATE users SET last_login = $2, updated_at = NOW() WHERE id = $1;

-- name: UserClearBan :exec
UPDATE users SET banned_at = NULL, banned_until = NULL, ban_reason = NULL, banned_by = NULL, updated_at = NOW() WHERE id = $1;

-- name: UserBan :exec
UPDATE users
SET banned_at = sqlc.arg(banned_at), banned_until = sqlc.narg(banned_until), ban_reason = sqlc.narg(ban_reason), banned_by = sqlc.narg(banned_by), updated_at = NOW()
WHERE id = sqlc.arg(id);

-- name: UserSoftDelete :exec
UPDATE users SET deleted_at = now(), updated_at = now() WHERE id = $1;

-- name: UserSetEmailAndUnverify :exec
UPDATE users SET email = lower(sqlc.arg(email)::text), email_verified = false, updated_at = NOW() WHERE id = $1;

-- name: UserSetAvatarURL :execrows
UPDATE users SET avatar_url = $2, updated_at = NOW() WHERE id = $1;

-- name: UserPasswordRow :one
SELECT password_hash, hash_algo
FROM user_passwords WHERE user_id = $1;

-- name: UserPasswordUpsert :exec
INSERT INTO user_passwords (user_id, password_hash, hash_algo)
VALUES ($1, $2, $3)
ON CONFLICT (user_id) DO UPDATE SET password_hash = EXCLUDED.password_hash, hash_algo = EXCLUDED.hash_algo, password_updated_at = NOW();

-- name: UserDeleteHard :exec
DELETE FROM users WHERE id = $1;

-- name: UserApplyEmailChange :exec
UPDATE users SET email = lower(sqlc.arg(email)::text), email_verified = true, updated_at = NOW() WHERE id = $1;

-- name: UserApplyPhoneChange :exec
UPDATE users SET phone_number = $2, phone_verified = true, updated_at = NOW() WHERE id = $1;

-- name: UserUsernameExists :one
SELECT EXISTS(SELECT 1 FROM name_claims WHERE owner_kind='user' AND persona='' AND name=lower(sqlc.arg(username)::text) AND (canonical OR expires_at IS NULL OR expires_at>sqlc.arg(at_time)::timestamptz));

-- name: UserCredentialVersion :one
SELECT credential_version, email, phone_number
FROM users WHERE id = $1;

-- name: UserCredentialVersionForUpdate :one
-- All credential changes acquire this account lock before credential/session rows.
SELECT credential_version, email, phone_number, deleted_at, banned_at, banned_until
FROM users WHERE id = $1 FOR UPDATE;

-- name: UserAdvanceCredentialVersion :exec
UPDATE users SET credential_version = credential_version + 1 WHERE id = $1;

-- name: UserPasswordRehash :exec
-- Opportunistic rehash cannot overwrite a password changed after verification.
UPDATE user_passwords SET password_hash = sqlc.arg(new_hash), hash_algo = 'argon2id'
WHERE user_id = sqlc.arg(user_id) AND password_hash = sqlc.arg(old_hash);
