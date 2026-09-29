-- Passkey queries.

-- name: PasskeysDeleteByUser :exec
UPDATE user_passkeys SET deleted_at = now() WHERE user_id = sqlc.arg(user_id)::uuid AND deleted_at IS NULL;
