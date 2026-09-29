-- API key queries.

-- name: APIKeysRevokeCreatedBy :exec
UPDATE api_keys SET revoked_at = now() WHERE created_by = sqlc.arg(user_id)::uuid AND revoked_at IS NULL;
