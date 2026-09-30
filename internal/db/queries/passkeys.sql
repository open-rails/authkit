-- Passkey queries.

-- name: PasskeysDeleteByUser :exec
UPDATE user_passkeys SET deleted_at = now() WHERE user_id = sqlc.arg(user_id)::uuid AND deleted_at IS NULL;

-- name: PasskeysByUser :many
-- The user's live passkeys for one relying party.
SELECT * FROM user_passkeys WHERE user_id = $1 AND rpid = $2 AND deleted_at IS NULL ORDER BY created_at, id;

-- name: PasskeyRename :execrows
UPDATE user_passkeys SET label = sqlc.narg(label) WHERE id = sqlc.arg(id) AND user_id = sqlc.arg(user_id) AND deleted_at IS NULL;

-- name: PasskeyDelete :execrows
-- A deleted passkey stays deleted; no row changes only for another account's or no passkey.
UPDATE user_passkeys SET deleted_at = COALESCE(deleted_at, now()) WHERE id = $1 AND user_id = $2;

-- name: PasskeyHandleUser :one
SELECT user_id FROM user_passkey_handles WHERE user_handle = $1;

-- name: PasskeyHandleByUser :one
SELECT user_handle FROM user_passkey_handles WHERE user_id = $1;

-- name: PasskeyHandleUpsert :one
-- A concurrent first registration keeps the handle already stored.
INSERT INTO user_passkey_handles (user_id, user_handle) VALUES ($1, $2)
ON CONFLICT (user_id) DO UPDATE SET user_handle = user_passkey_handles.user_handle
RETURNING user_handle;

-- name: PasskeyInsert :one
INSERT INTO user_passkeys
  (user_id, rpid, credential_id, public_key, sign_count, clone_warning, aaguid, transports, authenticator_attachment, flags, attestation_type, attestation_fmt, label)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)
RETURNING *;

-- name: PasskeyRecordUse :one
UPDATE user_passkeys
SET sign_count = $1, clone_warning = $2, flags = $3, last_used_at = now()
WHERE user_id = $4 AND rpid = $5 AND credential_id = $6 AND deleted_at IS NULL
RETURNING id;

-- name: PasskeyExistsForRP :one
SELECT EXISTS(SELECT 1 FROM user_passkeys WHERE user_id = $1 AND rpid = $2 AND deleted_at IS NULL);

-- name: PasskeyLiveForUpdate :one
SELECT id FROM user_passkeys WHERE id = $1 AND user_id = $2 AND deleted_at IS NULL FOR UPDATE;
