-- Two-factor queries. 2FA is on while the account has a factor; mfa_settings
-- holds its backup codes and goes with its last factor.

-- name: MFASettingsByUser :one
SELECT user_id, backup_codes, created_at, updated_at
FROM mfa_settings
WHERE user_id = $1;

-- name: MFASetBackupCodes :exec
UPDATE mfa_settings
SET backup_codes = sqlc.arg(backup_codes), updated_at = NOW()
WHERE user_id = sqlc.arg(user_id);

-- name: MFAConsumeBackupCode :execrows
-- Atomic single-use consume: removes the hashed code and reports rows affected.
-- 1 = this caller consumed it; 0 = code absent or already used. The
-- `= ANY(...)` guard makes the test-and-remove a single statement so concurrent
-- submissions of the same code cannot both succeed.
UPDATE mfa_settings
SET backup_codes = array_remove(backup_codes, sqlc.arg(code_hash)), updated_at = NOW()
WHERE user_id = sqlc.arg(user_id)
  AND sqlc.arg(code_hash) = ANY(backup_codes);

-- name: MFAUpsertSettings :exec
INSERT INTO mfa_settings (user_id, backup_codes, updated_at)
VALUES ($1, sqlc.arg(backup_codes), NOW())
ON CONFLICT (user_id) DO UPDATE SET
  backup_codes = EXCLUDED.backup_codes,
  updated_at = NOW();

-- name: MFAListFactorsByUser :many
SELECT id, user_id, method, phone_number, totp_secret, last_totp_step, is_default, created_at, updated_at, email
FROM mfa_factors
WHERE user_id = $1
ORDER BY is_default DESC, created_at ASC, id ASC;

-- name: MFAClearDefaultFactors :exec
UPDATE mfa_factors
SET is_default = false, updated_at = NOW()
WHERE user_id = $1;

-- name: MFAInsertFactor :one
INSERT INTO mfa_factors (user_id, method, phone_number, totp_secret, last_totp_step, is_default, email, updated_at)
VALUES (sqlc.arg(user_id), sqlc.arg(method), sqlc.narg(phone_number), sqlc.narg(totp_secret), sqlc.narg(last_totp_step), sqlc.arg(is_default), sqlc.narg(email), NOW())
RETURNING id, user_id, method, phone_number, totp_secret, last_totp_step, is_default, created_at, updated_at, email;

-- name: MFASetDefaultFactor :execrows
UPDATE mfa_factors
SET is_default = true, updated_at = NOW()
WHERE user_id = sqlc.arg(user_id) AND id = sqlc.arg(id);

-- name: MFADeleteFactor :execrows
DELETE FROM mfa_factors
WHERE user_id = sqlc.arg(user_id) AND id = sqlc.arg(id);

-- name: MFADeleteAllFactors :exec
DELETE FROM mfa_factors
WHERE user_id = $1;

-- name: MFAConsumeFactorTOTPStep :execrows
UPDATE mfa_factors
SET last_totp_step = sqlc.arg(step), updated_at = NOW()
WHERE id = sqlc.arg(id)
  AND user_id = sqlc.arg(user_id)
  AND method = 'totp'
  AND (last_totp_step IS NULL OR last_totp_step < sqlc.arg(step));

-- name: MFALockUser :one
SELECT id FROM users WHERE id = $1 FOR UPDATE;

-- name: MFAUsable :one
-- 2FA is on: the account has a factor.
SELECT EXISTS(SELECT 1 FROM mfa_factors WHERE user_id = sqlc.arg(user_id)::uuid)::boolean AS usable;

-- name: UserGroupRoles :many
-- Every role the user holds, with its group's persona.
SELECT a.permission_group_id, g.persona, a.role
FROM group_user_roles a JOIN permission_groups g ON g.id = a.permission_group_id
WHERE a.user_id = $1;

-- name: MFASetEmailFactorAddress :exec
UPDATE mfa_factors SET email = sqlc.arg(email)::text, updated_at = now()
WHERE user_id = sqlc.arg(user_id) AND method = 'email';
