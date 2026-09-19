-- Cross-site erasure handoff: obligations outlive the users row; purge selects
-- only accounts every required site acknowledged.

-- name: ErasureObligationRecord :exec
-- Captures the account's identifiers at deletion; a repeat keeps the original.
INSERT INTO account_erasure_obligations (user_id, email, username, phone_number)
SELECT id, email, username, phone_number FROM users WHERE id = sqlc.arg(user_id)::uuid
ON CONFLICT (user_id) DO NOTHING;

-- name: ErasureAcknowledgementsRequire :exec
-- Adds the deleting deployment's account issuers; an existing acknowledgement
-- is never reopened.
INSERT INTO account_erasure_acknowledgements (user_id, issuer, obligation_created_at)
SELECT o.user_id, issuer, o.created_at
FROM account_erasure_obligations o, unnest(sqlc.arg(issuers)::text[]) AS issuer
WHERE o.user_id = sqlc.arg(user_id)::uuid
ON CONFLICT (user_id, issuer) DO NOTHING;

-- name: ErasureObligationLock :one
SELECT user_id FROM account_erasure_obligations WHERE user_id = sqlc.arg(user_id)::uuid FOR UPDATE;

-- name: ErasureObligationRefreshPending :exec
-- Recomputes readiness under the caller-held row lock; never an increment.
UPDATE account_erasure_obligations o
SET pending_sites = (
  SELECT count(*) FROM account_erasure_acknowledgements a
  WHERE a.user_id = o.user_id AND a.acknowledged_at IS NULL)
WHERE o.user_id = sqlc.arg(user_id)::uuid;

-- name: ErasureObligationMarkPurged :exec
UPDATE account_erasure_obligations SET purged_at = now()
WHERE user_id = sqlc.arg(user_id)::uuid AND purged_at IS NULL;

-- name: ErasureObligationCloseIfSettled :execrows
-- Closed = identity purged and every required site acknowledged.
DELETE FROM account_erasure_obligations
WHERE user_id = sqlc.arg(user_id)::uuid AND purged_at IS NOT NULL AND pending_sites = 0;

-- name: ErasurePurgeCandidates :many
-- Index-ordered page of accounts deleted before the cutoff that every required
-- site acknowledged; an unacknowledged backlog is never walked.
-- Qualified ORDER BY: an unqualified user_id would bind to the ::text output
-- column and cost an extra sort.
SELECT o.user_id::text
FROM account_erasure_obligations o
WHERE o.purged_at IS NULL AND o.pending_sites = 0 AND o.created_at < sqlc.arg(cutoff)::timestamptz
ORDER BY o.created_at, o.user_id
LIMIT sqlc.arg(max_rows)::bigint;

-- name: ErasureObligationsPendingForIssuer :many
-- Keyset page of obligations the issuer has not acknowledged, oldest first.
SELECT o.user_id, o.email, o.username, o.phone_number, a.obligation_created_at AS created_at, o.purged_at
FROM account_erasure_acknowledgements a
JOIN account_erasure_obligations o ON o.user_id = a.user_id
WHERE a.issuer = sqlc.arg(issuer)::text AND a.acknowledged_at IS NULL
  AND (a.obligation_created_at, a.user_id) > (sqlc.arg(after_created_at)::timestamptz, sqlc.arg(after_user_id)::uuid)
ORDER BY a.obligation_created_at, a.user_id
LIMIT sqlc.arg(max_rows)::bigint;

-- name: ErasureAcknowledge :execrows
UPDATE account_erasure_acknowledgements SET acknowledged_at = now()
WHERE user_id = sqlc.arg(user_id)::uuid AND issuer = sqlc.arg(issuer)::text AND acknowledged_at IS NULL;

-- name: ErasureObligationsBacklog :many
SELECT a.issuer, count(*)::bigint AS pending, min(a.obligation_created_at)::timestamptz AS oldest_created_at
FROM account_erasure_acknowledgements a
WHERE a.acknowledged_at IS NULL
GROUP BY a.issuer
ORDER BY a.issuer;
