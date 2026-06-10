-- Two-factor settings queries (core/service.go).

-- name: TwoFactorEnable :exec
INSERT INTO profiles.two_factor_settings (user_id, enabled, method, phone_number, backup_codes, updated_at)
VALUES ($1, true, sqlc.arg(method), sqlc.narg(phone_number), sqlc.arg(backup_codes), NOW())
ON CONFLICT (user_id) DO UPDATE SET
  enabled = true,
  method = EXCLUDED.method,
  phone_number = EXCLUDED.phone_number,
  backup_codes = EXCLUDED.backup_codes,
  updated_at = NOW();

-- name: TwoFactorDisable :exec
UPDATE profiles.two_factor_settings
SET enabled = false, updated_at = NOW()
WHERE user_id = $1;

-- name: TwoFactorSettingsByUser :one
SELECT user_id, enabled, method, phone_number, backup_codes, created_at, updated_at
FROM profiles.two_factor_settings
WHERE user_id = $1;

-- name: TwoFactorSetBackupCodes :exec
UPDATE profiles.two_factor_settings
SET backup_codes = sqlc.arg(backup_codes), updated_at = NOW()
WHERE user_id = sqlc.arg(user_id);
