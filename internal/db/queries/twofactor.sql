-- Two-factor settings queries (core/service.go).

-- name: TwoFactorEnable :exec
INSERT INTO profiles.two_factor_settings (user_id, enabled, method, phone_number, backup_codes, totp_secret, last_totp_step, updated_at)
VALUES ($1, true, sqlc.arg(method), sqlc.narg(phone_number), sqlc.arg(backup_codes), sqlc.narg(totp_secret), NULL, NOW())
ON CONFLICT (user_id) DO UPDATE SET
  enabled = true,
  method = EXCLUDED.method,
  phone_number = EXCLUDED.phone_number,
  backup_codes = EXCLUDED.backup_codes,
  totp_secret = EXCLUDED.totp_secret,
  last_totp_step = NULL,
  updated_at = NOW();

-- name: TwoFactorDisable :exec
UPDATE profiles.two_factor_settings
SET enabled = false, updated_at = NOW()
WHERE user_id = $1;

-- name: TwoFactorDelete :exec
DELETE FROM profiles.two_factor_settings
WHERE user_id = $1;

-- name: TwoFactorSettingsByUser :one
SELECT user_id, enabled, method, phone_number, backup_codes, totp_secret, last_totp_step, created_at, updated_at
FROM profiles.two_factor_settings
WHERE user_id = $1;

-- name: TwoFactorSetBackupCodes :exec
UPDATE profiles.two_factor_settings
SET backup_codes = sqlc.arg(backup_codes), updated_at = NOW()
WHERE user_id = sqlc.arg(user_id);

-- name: TwoFactorConsumeTOTPStep :execrows
UPDATE profiles.two_factor_settings
SET last_totp_step = sqlc.arg(step), updated_at = NOW()
WHERE user_id = sqlc.arg(user_id)
  AND enabled = true
  AND method = 'totp'
  AND (last_totp_step IS NULL OR last_totp_step < sqlc.arg(step));

-- name: TwoFactorUpsertSettings :exec
INSERT INTO profiles.two_factor_settings (user_id, enabled, method, phone_number, backup_codes, totp_secret, last_totp_step, updated_at)
VALUES ($1, true, sqlc.arg(method), sqlc.narg(phone_number), sqlc.arg(backup_codes), sqlc.narg(totp_secret), sqlc.narg(last_totp_step), NOW())
ON CONFLICT (user_id) DO UPDATE SET
  enabled = true,
  method = EXCLUDED.method,
  phone_number = EXCLUDED.phone_number,
  backup_codes = EXCLUDED.backup_codes,
  totp_secret = EXCLUDED.totp_secret,
  last_totp_step = EXCLUDED.last_totp_step,
  updated_at = NOW();

-- name: TwoFactorListFactorsByUser :many
SELECT id, user_id, method, phone_number, totp_secret, last_totp_step, is_default, enabled, created_at, updated_at
FROM profiles.two_factor_factors
WHERE user_id = $1 AND enabled = true
ORDER BY is_default DESC, created_at ASC, id ASC;

-- name: TwoFactorDefaultFactorByUser :one
SELECT id, user_id, method, phone_number, totp_secret, last_totp_step, is_default, enabled, created_at, updated_at
FROM profiles.two_factor_factors
WHERE user_id = $1 AND enabled = true
ORDER BY is_default DESC, created_at ASC, id ASC
LIMIT 1;

-- name: TwoFactorFactorByUserMethod :one
SELECT id, user_id, method, phone_number, totp_secret, last_totp_step, is_default, enabled, created_at, updated_at
FROM profiles.two_factor_factors
WHERE user_id = sqlc.arg(user_id) AND method = sqlc.arg(method) AND enabled = true;

-- name: TwoFactorClearDefaultFactors :exec
UPDATE profiles.two_factor_factors
SET is_default = false, updated_at = NOW()
WHERE user_id = $1 AND enabled = true;

-- name: TwoFactorUpsertFactor :one
INSERT INTO profiles.two_factor_factors (user_id, method, phone_number, totp_secret, last_totp_step, is_default, enabled, updated_at)
VALUES (sqlc.arg(user_id), sqlc.arg(method), sqlc.narg(phone_number), sqlc.narg(totp_secret), sqlc.narg(last_totp_step), sqlc.arg(is_default), true, NOW())
ON CONFLICT (user_id, method) WHERE enabled = true DO UPDATE SET
  phone_number = EXCLUDED.phone_number,
  totp_secret = EXCLUDED.totp_secret,
  last_totp_step = EXCLUDED.last_totp_step,
  is_default = profiles.two_factor_factors.is_default OR EXCLUDED.is_default,
  enabled = true,
  updated_at = NOW()
RETURNING id, user_id, method, phone_number, totp_secret, last_totp_step, is_default, enabled, created_at, updated_at;

-- name: TwoFactorSetDefaultFactor :execrows
UPDATE profiles.two_factor_factors
SET is_default = true, updated_at = NOW()
WHERE user_id = sqlc.arg(user_id) AND id = sqlc.arg(id) AND enabled = true;

-- name: TwoFactorDisableFactor :execrows
UPDATE profiles.two_factor_factors
SET enabled = false, is_default = false, updated_at = NOW()
WHERE user_id = sqlc.arg(user_id) AND id = sqlc.arg(id) AND enabled = true;

-- name: TwoFactorDisableAllFactors :exec
UPDATE profiles.two_factor_factors
SET enabled = false, is_default = false, updated_at = NOW()
WHERE user_id = $1 AND enabled = true;

-- name: TwoFactorConsumeFactorTOTPStep :execrows
UPDATE profiles.two_factor_factors
SET last_totp_step = sqlc.arg(step), updated_at = NOW()
WHERE id = sqlc.arg(id)
  AND user_id = sqlc.arg(user_id)
  AND enabled = true
  AND method = 'totp'
  AND (last_totp_step IS NULL OR last_totp_step < sqlc.arg(step));
