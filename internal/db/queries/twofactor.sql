-- Two-factor queries (core/service.go).
--
-- #125: factors are hard-deleted (no per-factor `enabled` flag). mfa_settings
-- holds only the account-level gate (`enabled`) + `backup_codes`; per-factor data
-- (method/phone/totp_secret/last_totp_step) lives ONLY on mfa_factors.

-- name: MFADisable :exec
UPDATE profiles.mfa_settings
SET enabled = false, updated_at = NOW()
WHERE user_id = $1;

-- name: MFADelete :exec
DELETE FROM profiles.mfa_settings
WHERE user_id = $1;

-- name: MFASettingsByUser :one
SELECT user_id, enabled, backup_codes, created_at, updated_at
FROM profiles.mfa_settings
WHERE user_id = $1;

-- name: MFASetBackupCodes :exec
UPDATE profiles.mfa_settings
SET backup_codes = sqlc.arg(backup_codes), updated_at = NOW()
WHERE user_id = sqlc.arg(user_id);

-- name: MFAConsumeBackupCode :execrows
-- Atomic single-use consume: removes the hashed code and reports rows affected.
-- 1 = this caller consumed it; 0 = code absent / already used / 2FA disabled. The
-- `= ANY(...)` guard makes the test-and-remove a single statement so concurrent
-- submissions of the same code cannot both succeed.
UPDATE profiles.mfa_settings
SET backup_codes = array_remove(backup_codes, sqlc.arg(code_hash)), updated_at = NOW()
WHERE user_id = sqlc.arg(user_id)
  AND enabled = true
  AND sqlc.arg(code_hash) = ANY(backup_codes);

-- name: MFAUpsertSettings :exec
INSERT INTO profiles.mfa_settings (user_id, enabled, backup_codes, updated_at)
VALUES ($1, true, sqlc.arg(backup_codes), NOW())
ON CONFLICT (user_id) DO UPDATE SET
  enabled = true,
  backup_codes = EXCLUDED.backup_codes,
  updated_at = NOW();

-- name: MFAListFactorsByUser :many
SELECT id, user_id, method, phone_number, totp_secret, last_totp_step, is_default, created_at, updated_at
FROM profiles.mfa_factors
WHERE user_id = $1
ORDER BY is_default DESC, created_at ASC, id ASC;

-- name: MFAClearDefaultFactors :exec
UPDATE profiles.mfa_factors
SET is_default = false, updated_at = NOW()
WHERE user_id = $1;

-- name: MFAUpsertFactor :one
INSERT INTO profiles.mfa_factors (user_id, method, phone_number, totp_secret, last_totp_step, is_default, updated_at)
VALUES (sqlc.arg(user_id), sqlc.arg(method), sqlc.narg(phone_number), sqlc.narg(totp_secret), sqlc.narg(last_totp_step), sqlc.arg(is_default), NOW())
ON CONFLICT (user_id, method) DO UPDATE SET
  phone_number = EXCLUDED.phone_number,
  totp_secret = EXCLUDED.totp_secret,
  last_totp_step = EXCLUDED.last_totp_step,
  is_default = profiles.mfa_factors.is_default OR EXCLUDED.is_default,
  updated_at = NOW()
RETURNING id, user_id, method, phone_number, totp_secret, last_totp_step, is_default, created_at, updated_at;

-- name: MFASetDefaultFactor :execrows
UPDATE profiles.mfa_factors
SET is_default = true, updated_at = NOW()
WHERE user_id = sqlc.arg(user_id) AND id = sqlc.arg(id);

-- name: MFADeleteFactor :execrows
DELETE FROM profiles.mfa_factors
WHERE user_id = sqlc.arg(user_id) AND id = sqlc.arg(id);

-- name: MFADeleteAllFactors :exec
DELETE FROM profiles.mfa_factors
WHERE user_id = $1;

-- name: MFAConsumeFactorTOTPStep :execrows
UPDATE profiles.mfa_factors
SET last_totp_step = sqlc.arg(step), updated_at = NOW()
WHERE id = sqlc.arg(id)
  AND user_id = sqlc.arg(user_id)
  AND method = 'totp'
  AND (last_totp_step IS NULL OR last_totp_step < sqlc.arg(step));
