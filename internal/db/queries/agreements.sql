-- Agreement acceptances (#449): append-only; a repeat of one version is kept
-- as first given.

-- name: UserAgreementInsert :exec
INSERT INTO user_agreements (user_id, key, version, channel, ip_addr, user_agent)
VALUES (sqlc.arg(user_id)::uuid, sqlc.arg(key), sqlc.arg(version), sqlc.arg(channel), sqlc.narg(ip_addr)::inet, sqlc.narg(user_agent))
ON CONFLICT (user_id, key, version) DO NOTHING;

-- name: UserAgreementsByUser :many
SELECT key, version, accepted_at, channel
FROM user_agreements
WHERE user_id = sqlc.arg(user_id)::uuid
ORDER BY key, accepted_at, version;
