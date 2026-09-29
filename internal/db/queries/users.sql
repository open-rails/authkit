-- User-row queries. A user read selects the whole row, so every read returns
-- db.User: the engine's one user type.

-- name: UserByID :one
SELECT * FROM users WHERE id = $1;

-- name: UserByEmail :one
SELECT * FROM users WHERE email = lower(sqlc.arg(email)::text)::public.citext;

-- name: UserByPhone :one
SELECT * FROM users WHERE phone_number = $1;

-- name: UserByUsername :one
SELECT * FROM users WHERE username = sqlc.arg(username)::text::public.citext;

-- name: UsersByIDs :many
SELECT * FROM users WHERE id = ANY(sqlc.arg(ids)::uuid[]);

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
RETURNING *;

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

-- name: UserSetLastLogin :exec
UPDATE users SET last_login = $2, updated_at = NOW() WHERE id = $1;

-- name: UserClearBan :exec
UPDATE users SET banned_at = NULL, banned_until = NULL, ban_reason = NULL, banned_by = NULL, updated_at = NOW() WHERE id = $1;

-- name: UserBan :exec
UPDATE users
SET banned_at = sqlc.arg(banned_at), banned_until = sqlc.narg(banned_until), ban_reason = sqlc.narg(ban_reason), banned_by = sqlc.narg(banned_by), updated_at = NOW()
WHERE id = sqlc.arg(id);

-- name: UserSoftDelete :exec
UPDATE users SET deleted_at = statement_timestamp(), updated_at = statement_timestamp() WHERE id = $1;

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

-- name: UserPasswordDelete :exec
DELETE FROM user_passwords WHERE user_id = $1;

-- name: UserNameForUpdate :one
SELECT username, last_renamed_at FROM users WHERE id = $1 AND deleted_at IS NULL FOR UPDATE;

-- name: UserSetUsernameSpelling :exec
-- Same name, new display spelling: no name claim, alias or cooldown.
UPDATE users SET username = sqlc.arg(username), updated_at = sqlc.arg(at_time)::timestamptz WHERE id = sqlc.arg(id);

-- name: UserRename :exec
UPDATE users SET username = sqlc.arg(username), last_renamed_at = sqlc.arg(at_time)::timestamptz, updated_at = sqlc.arg(at_time)::timestamptz
WHERE id = sqlc.arg(id);

-- name: ContactState :one
-- An account is unproven when it has an address and none is verified.
SELECT ((email IS NOT NULL OR phone_number IS NOT NULL)
        AND NOT ((email IS NOT NULL AND email_verified) OR (phone_number IS NOT NULL AND phone_verified)))::boolean AS unproven,
       COALESCE(email::text, phone_number, '')::text AS identifier,
       (CASE WHEN email IS NOT NULL THEN 'email' ELSE 'phone' END)::text AS channel
FROM users WHERE id = $1;

-- name: ContactStateForUpdate :one
SELECT ((email IS NOT NULL OR phone_number IS NOT NULL)
        AND NOT ((email IS NOT NULL AND email_verified) OR (phone_number IS NOT NULL AND phone_verified)))::boolean AS unproven,
       COALESCE(email::text, phone_number, '')::text AS identifier,
       (CASE WHEN email IS NOT NULL THEN 'email' ELSE 'phone' END)::text AS channel
FROM users WHERE id = $1 FOR UPDATE;

-- name: UserSetEmail :exec
-- A new address is unverified; setting the current one changes nothing.
UPDATE users SET email = sqlc.narg(email), email_verified = false, updated_at = now()
WHERE id = sqlc.arg(id) AND email IS DISTINCT FROM sqlc.narg(email)::text::public.citext;

-- name: UserSetPhone :exec
UPDATE users SET phone_number = sqlc.narg(phone_number), phone_verified = false, updated_at = now()
WHERE id = sqlc.arg(id) AND phone_number IS DISTINCT FROM sqlc.narg(phone_number);

-- name: UserSetEmailVerifiedIfPresent :execrows
-- Verifying needs an address; no row changes without one.
UPDATE users SET email_verified = sqlc.arg(verified), updated_at = now()
WHERE id = sqlc.arg(id) AND (NOT sqlc.arg(verified)::boolean OR email IS NOT NULL);

-- name: UserSetPhoneVerifiedIfPresent :execrows
UPDATE users SET phone_verified = sqlc.arg(verified), updated_at = now()
WHERE id = sqlc.arg(id) AND (NOT sqlc.arg(verified)::boolean OR phone_number IS NOT NULL);

-- name: UserSetAvatarURL :exec
UPDATE users SET avatar_url = sqlc.narg(avatar_url), updated_at = now() WHERE id = sqlc.arg(id);

-- name: UserPatchMetadata :exec
-- Merges patch into the metadata and removes drop_keys.
UPDATE users SET metadata = (COALESCE(metadata, '{}'::jsonb) || sqlc.arg(patch)::jsonb) - sqlc.arg(drop_keys)::text[], updated_at = now()
WHERE id = sqlc.arg(id);

-- name: UserBanInForce :one
SELECT (banned_at IS NOT NULL AND (banned_until IS NULL OR banned_until > now()))::boolean AS in_force
FROM users WHERE id = $1;

-- name: MFASettingsDelete :exec
DELETE FROM mfa_settings WHERE user_id = $1;

-- name: AccountDeletionSetDeletedBy :exec
-- Records who deleted an account that is already deleted.
UPDATE account_deletions SET deleted_by = sqlc.narg(deleted_by)::uuid WHERE user_id = sqlc.arg(user_id) AND state = 'deleted';

-- name: AccountDeletionPurgeNow :one
-- Closes the recovery window of a deleted account now.
UPDATE account_deletions SET purge_at = statement_timestamp()
WHERE user_id = $1 AND state = 'deleted'
RETURNING id, user_id, deleted_at, purge_at;
