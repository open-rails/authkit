-- User-row queries (core/service.go).

-- name: UserEmailByID :one
SELECT email FROM profiles.users WHERE id = $1;

-- name: UserByID :one
SELECT id, email, phone_number, username, discord_username, email_verified, COALESCE(phone_verified, false)::boolean AS phone_verified, banned_at, banned_until, ban_reason, banned_by, deleted_at, biography, created_at, updated_at, last_login
FROM profiles.users WHERE id = $1;

-- name: UserByEmail :one
SELECT id, email, phone_number, username, discord_username, email_verified, COALESCE(phone_verified, false)::boolean AS phone_verified, banned_at, banned_until, ban_reason, banned_by, deleted_at, biography, created_at, updated_at, last_login
FROM profiles.users WHERE email = lower(sqlc.arg(email)::text)::citext;

-- name: UserByUsername :one
SELECT id, email, phone_number, username, discord_username, email_verified, COALESCE(phone_verified, false)::boolean AS phone_verified, banned_at, banned_until, ban_reason, banned_by, deleted_at, biography, created_at, updated_at, last_login
FROM profiles.users WHERE username = $1;

-- name: UserByPhone :one
SELECT id, email, phone_number, username, discord_username, email_verified, COALESCE(phone_verified, false)::boolean AS phone_verified, banned_at, banned_until, ban_reason, banned_by, deleted_at, biography, created_at, updated_at, last_login
FROM profiles.users WHERE phone_number = $1;

-- name: UserSetPhoneVerifiedByID :exec
UPDATE profiles.users SET phone_verified = $2, updated_at = NOW() WHERE id = $1;

-- name: UserSetPhoneVerifiedByIDAndPhone :exec
UPDATE profiles.users
SET phone_verified = true
WHERE id = $1 AND phone_number = $2;

-- name: UserEmailOrUsernameTaken :one
SELECT
  EXISTS(SELECT 1 FROM profiles.users WHERE email = lower(sqlc.arg(email)::text)::citext)::boolean AS email_taken,
  EXISTS(SELECT 1 FROM profiles.users WHERE username = sqlc.arg(username)::text::citext)::boolean AS username_taken;

-- name: UserPhoneOrUsernameTaken :one
SELECT
  EXISTS(SELECT 1 FROM profiles.users WHERE phone_number = sqlc.arg(phone)::text)::boolean AS phone_taken,
  EXISTS(SELECT 1 FROM profiles.users WHERE username = sqlc.arg(username)::text::citext)::boolean AS username_taken;

-- name: UserSetPreferredLocale :exec
UPDATE profiles.users
SET preferred_locale = $2,
    preferred_locale_source = $3,
    preferred_locale_updated_at = now(),
    updated_at = now()
WHERE id = sqlc.arg(id)::uuid;

-- name: UserPreferredLocale :one
SELECT COALESCE(preferred_locale, '')::text AS locale,
       COALESCE(preferred_locale_source, '')::text AS source,
       preferred_locale_updated_at
FROM profiles.users
WHERE id = sqlc.arg(id)::uuid;

-- name: UserInsert :one
INSERT INTO profiles.users (id, email, username)
VALUES (sqlc.arg(id)::uuid, NULLIF(lower(sqlc.arg(email)::text), ''), sqlc.arg(username))
RETURNING id, email, username, email_verified, banned_at, deleted_at;

-- name: UserImportInsert :exec
INSERT INTO profiles.users (
  id, email, phone_number, username, email_verified, phone_verified,
  banned_at, banned_until, ban_reason, banned_by, metadata, created_at, updated_at
)
VALUES (
  sqlc.arg(id)::uuid, sqlc.narg(email), sqlc.narg(phone_number), sqlc.arg(username), sqlc.arg(email_verified), sqlc.arg(phone_verified),
  sqlc.narg(banned_at), sqlc.narg(banned_until), sqlc.narg(ban_reason), sqlc.narg(banned_by)::uuid, sqlc.arg(metadata)::jsonb, sqlc.arg(created_at), sqlc.arg(updated_at)
);

-- name: UserImportUpdate :one
UPDATE profiles.users
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
UPDATE profiles.users SET email_verified = $2, updated_at = NOW() WHERE id = $1;

-- name: UserPasswordInsert :exec
INSERT INTO profiles.user_passwords (user_id, password_hash, hash_algo)
VALUES ($1, $2, 'argon2id');

-- name: UserSetPhoneAndVerified :exec
UPDATE profiles.users
SET phone_number = $2, phone_verified = $3, updated_at = NOW()
WHERE id = $1;

-- name: UserSetLastLogin :exec
UPDATE profiles.users SET last_login = $2, updated_at = NOW() WHERE id = $1;

-- name: UserClearBan :exec
UPDATE profiles.users SET banned_at = NULL, banned_until = NULL, ban_reason = NULL, banned_by = NULL, updated_at = NOW() WHERE id = $1;

-- name: UserBan :exec
UPDATE profiles.users
SET banned_at = sqlc.arg(banned_at), banned_until = sqlc.narg(banned_until), ban_reason = sqlc.narg(ban_reason), banned_by = sqlc.narg(banned_by), updated_at = NOW()
WHERE id = sqlc.arg(id);

-- name: UserSoftDelete :exec
UPDATE profiles.users SET deleted_at = now(), updated_at = now() WHERE id = $1;

-- name: UserRestore :exec
UPDATE profiles.users SET deleted_at = NULL, updated_at = now() WHERE id = $1;

-- name: UserUsernameByID :one
SELECT username::text FROM profiles.users WHERE id = sqlc.arg(id)::uuid;

-- name: UserLastRenamedAt :one
SELECT renamed_at
FROM   profiles.user_renames
WHERE  user_id = sqlc.arg(user_id)::uuid
ORDER  BY renamed_at DESC
LIMIT  1;

-- name: UserSetUsername :exec
UPDATE profiles.users SET username = $2, updated_at = NOW() WHERE id = $1;

-- name: UserRenameInsert :exec
INSERT INTO profiles.user_renames (user_id, from_slug)
VALUES (sqlc.arg(user_id)::uuid, $2);

-- name: PersonalOrgIDSlugByOwner :one
SELECT id::text, slug
FROM profiles.orgs
WHERE owner_user_id = sqlc.arg(owner_user_id)::uuid AND is_personal = true AND deleted_at IS NULL;

-- name: PersonalOrgInsertBasic :exec
INSERT INTO profiles.orgs (id, slug, is_personal, owner_user_id)
VALUES (sqlc.arg(id)::uuid, $2, true, sqlc.arg(owner_user_id)::uuid);

-- OrgUpdateSlugUnconditional intentionally has no deleted_at filter — it
-- rides the user-rename transaction in updateUsernameImpl.
-- name: OrgUpdateSlugUnconditional :exec
UPDATE profiles.orgs SET slug = $1, updated_at = now() WHERE id = sqlc.arg(id)::uuid;

-- name: UserSetEmailAndUnverify :exec
UPDATE profiles.users SET email = lower(sqlc.arg(email)::text), email_verified = false, updated_at = NOW() WHERE id = $1;

-- name: UserSetBiography :exec
UPDATE profiles.users SET biography = $2, updated_at = NOW() WHERE id = $1;

-- name: UserPasswordRow :one
SELECT password_hash, hash_algo, COALESCE(hash_params, '{}'::jsonb)::jsonb AS hash_params
FROM profiles.user_passwords WHERE user_id = $1;

-- name: UserPasswordUpsert :exec
INSERT INTO profiles.user_passwords (user_id, password_hash, hash_algo, hash_params)
VALUES ($1, $2, $3, $4)
ON CONFLICT (user_id) DO UPDATE SET password_hash = EXCLUDED.password_hash, hash_algo = EXCLUDED.hash_algo, hash_params = EXCLUDED.hash_params, password_updated_at = NOW();

-- name: UserDeleteHard :exec
DELETE FROM profiles.users WHERE id = $1;

-- SessionsRevokeAllQuiet is AdminDeleteUser's pre-delete sweep; unlike
-- SessionsRevokeAll it returns nothing (no per-session revoke logging).
-- name: SessionsRevokeAllQuiet :exec
UPDATE profiles.refresh_sessions SET revoked_at = now() WHERE user_id = $1 AND issuer = $2;

-- name: UserDiscordUsername :one
SELECT discord_username FROM profiles.users WHERE id = $1;

-- name: UserEmailOrUsernameExists :one
SELECT EXISTS(
  SELECT 1 FROM profiles.users
  WHERE email = lower(sqlc.arg(email)::text)::citext OR username = sqlc.arg(username)::text::citext
);

-- name: UserPhoneOrUsernameExists :one
SELECT EXISTS(
  SELECT 1 FROM profiles.users
  WHERE phone_number = sqlc.arg(phone)::text OR username = sqlc.arg(username)::text::citext
);

-- name: UserApplyEmailChange :exec
UPDATE profiles.users SET email = lower(sqlc.arg(email)::text), email_verified = true, updated_at = NOW() WHERE id = $1;

-- name: UserApplyPhoneChange :exec
UPDATE profiles.users SET phone_number = $2, phone_verified = true, updated_at = NOW() WHERE id = $1;

-- name: UsersPurgeCandidates :many
SELECT id::text
FROM profiles.users
WHERE deleted_at IS NOT NULL AND deleted_at < sqlc.arg(cutoff)
ORDER BY deleted_at ASC
LIMIT sqlc.arg(max_rows)::bigint;

-- name: UserUsernameExists :one
SELECT EXISTS(SELECT 1 FROM profiles.users WHERE username = $1);
