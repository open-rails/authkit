-- Maintenance sweep of terminal credentials, retained for inspection until
-- cutoff. Each call deletes one bounded batch, locking only that batch (SKIP
-- LOCKED) so concurrent sweeps make progress.

-- name: InviteLinksDeleteExpiredBatch :exec
WITH batch AS (
    SELECT id FROM group_invite_links WHERE LEAST(redeemed_at, revoked_at, expires_at) < sqlc.arg(cutoff)::timestamptz
    ORDER BY LEAST(redeemed_at, revoked_at, expires_at), id
    LIMIT sqlc.arg(batch_size)::bigint FOR UPDATE SKIP LOCKED)
DELETE FROM group_invite_links WHERE id IN (SELECT id FROM batch);

-- name: AccountInvitesDeleteExpiredBatch :exec
WITH batch AS (
    SELECT id FROM account_registration_invites WHERE LEAST(consumed_at, revoked_at, expires_at) < sqlc.arg(cutoff)::timestamptz
    ORDER BY LEAST(consumed_at, revoked_at, expires_at), id
    LIMIT sqlc.arg(batch_size)::bigint FOR UPDATE SKIP LOCKED)
DELETE FROM account_registration_invites WHERE id IN (SELECT id FROM batch);

-- name: APIKeysDeleteExpiredBatch :exec
WITH batch AS (
    SELECT id FROM api_keys WHERE LEAST(revoked_at, expires_at) < sqlc.arg(cutoff)::timestamptz
    ORDER BY LEAST(revoked_at, expires_at), id
    LIMIT sqlc.arg(batch_size)::bigint FOR UPDATE SKIP LOCKED)
DELETE FROM api_keys WHERE id IN (SELECT id FROM batch);
