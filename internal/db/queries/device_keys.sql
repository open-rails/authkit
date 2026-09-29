-- Device key queries. A key read returns db.UserDeviceKey.

-- name: DeviceKeyByPublicKey :one
SELECT * FROM user_device_keys WHERE public_key = $1;

-- name: DeviceKeyEnrollUserInsert :execrows
-- The account a device-key enrollment creates; the emailed code proved its address.
INSERT INTO users (id, email, email_verified) VALUES ($1, sqlc.arg(email)::text, true) ON CONFLICT DO NOTHING;

-- name: DeviceKeyMarkMFAProven :exec
UPDATE user_device_keys SET mfa_proven_at = now() WHERE id = $1;

-- name: DeviceKeyInsert :one
INSERT INTO user_device_keys (user_id, public_key, label, mfa_proven_at)
VALUES (sqlc.arg(user_id), sqlc.arg(public_key), sqlc.narg(label), CASE WHEN sqlc.arg(mfa_proven)::boolean THEN now() END)
RETURNING *;

-- name: DeviceKeyActive :one
SELECT * FROM user_device_keys WHERE id = $1 AND revoked_at IS NULL;

-- name: DeviceKeyTouch :one
UPDATE user_device_keys SET last_used_at = now()
WHERE id = $1 AND user_id = $2 AND revoked_at IS NULL
RETURNING *;

-- name: DeviceKeyIsActive :one
SELECT EXISTS(SELECT 1 FROM user_device_keys WHERE id = $1 AND user_id = $2 AND revoked_at IS NULL);

-- name: DeviceKeyIsActiveForUpdate :one
SELECT EXISTS(SELECT 1 FROM user_device_keys WHERE id = $1 AND user_id = $2 AND revoked_at IS NULL FOR UPDATE);

-- name: DeviceKeysByUser :many
SELECT * FROM user_device_keys WHERE user_id = $1 ORDER BY created_at, id;

-- name: DeviceKeyPublicKeysActive :many
SELECT public_key FROM user_device_keys WHERE user_id = $1 AND revoked_at IS NULL ORDER BY created_at, id;

-- name: DeviceKeyRevoke :execrows
UPDATE user_device_keys SET revoked_at = COALESCE(revoked_at, now()) WHERE id = $1 AND user_id = $2;

-- name: DeviceKeysRevokeAllExcept :execrows
-- Ends every live device key of the account but keep_id (optional), e.g. the
-- one presenting a credential change.
UPDATE user_device_keys SET revoked_at = now()
WHERE user_id = sqlc.arg(user_id)::uuid AND revoked_at IS NULL
  AND (sqlc.narg(keep_id)::uuid IS NULL OR id <> sqlc.narg(keep_id)::uuid);
