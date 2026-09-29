-- Account deletion lifecycle: the recovery window (account_deletions), the
-- per-issuer delivery receipts River works off, and each issuer's River fleet.

-- name: StatementTimestamp :one
SELECT statement_timestamp()::timestamptz AS now;

-- name: AccountDeletionInsert :one
-- Starts the recovery window from the account's own deleted_at.
INSERT INTO account_deletions (user_id, deleted_at, purge_at, recipients, deleted_by)
SELECT id, deleted_at, deleted_at + interval '720 hours', sqlc.arg(recipients)::text[], sqlc.narg(deleted_by)::uuid
FROM users WHERE id = sqlc.arg(user_id)::uuid
RETURNING *;

-- name: AccountDeletionForUpdate :one
SELECT * FROM account_deletions WHERE id = $1 FOR UPDATE;

-- name: AccountDeletionUser :one
SELECT user_id FROM account_deletions WHERE id = $1;

-- name: AccountDeletionOpenForUser :one
SELECT id FROM account_deletions WHERE user_id = $1 AND state IN ('deleted', 'finalizing');

-- name: AccountDeletionRecoverable :one
-- The account's current deletion while it can still be undone.
SELECT * FROM account_deletions
WHERE user_id = sqlc.arg(user_id) AND state = 'deleted' AND deleted_at = sqlc.arg(deleted_at)
  AND purge_at > statement_timestamp();

-- name: AccountDeletionPurgeWindow :one
SELECT statement_timestamp()::timestamptz AS now, purge_at FROM account_deletions
WHERE id = sqlc.arg(id) AND user_id = sqlc.arg(user_id) AND state = 'deleted' AND purge_at > statement_timestamp();

-- name: AccountDeletionStateForUpdate :one
SELECT state FROM account_deletions WHERE id = $1 FOR UPDATE;

-- name: AccountDeletionSetFinalizing :exec
UPDATE account_deletions SET state = 'finalizing' WHERE id = $1;

-- name: AccountDeletionSetPurged :exec
UPDATE account_deletions SET state = 'purged', purged_at = statement_timestamp() WHERE id = $1;

-- name: AccountDeletionSetRestored :exec
UPDATE account_deletions SET state = 'restored', restored_at = statement_timestamp() WHERE id = $1;

-- name: UserRestore :exec
-- Clearing deleted_at fires the credential-version trigger, like deletion.
UPDATE users SET deleted_at = NULL, updated_at = statement_timestamp() WHERE id = $1;

-- name: GroupsOwnedByUser :many
SELECT permission_group_id FROM group_user_roles WHERE user_id = $1 AND role = 'owner' ORDER BY permission_group_id;

-- name: AccountDeletionsDeleteTerminalBatch :execrows
-- One bounded batch of restored/purged deletions past cutoff with no pending
-- receipt; completed receipts go with them (FK cascade).
WITH batch AS (
    SELECT d.id FROM account_deletions d
    WHERE d.state IN ('restored', 'purged') AND COALESCE(d.restored_at, d.purged_at) < sqlc.arg(cutoff)::timestamptz
      AND NOT EXISTS (SELECT 1 FROM account_deletion_deliveries e WHERE e.deletion_id = d.id AND e.completed_at IS NULL)
    ORDER BY COALESCE(d.restored_at, d.purged_at), d.id
    LIMIT sqlc.arg(batch_size)::bigint FOR UPDATE SKIP LOCKED)
DELETE FROM account_deletions WHERE id IN (SELECT id FROM batch);

-- name: AccountDeletionDeliveryInsert :one
-- No row (pgx.ErrNoRows) when the receipt already exists.
INSERT INTO account_deletion_deliveries (deletion_id, user_id, issuer, stage)
VALUES (sqlc.arg(deletion_id), sqlc.arg(user_id), sqlc.arg(issuer), sqlc.arg(stage))
ON CONFLICT (deletion_id, issuer, stage) DO NOTHING
RETURNING id;

-- name: AccountDeletionDeliveryUser :one
SELECT user_id FROM account_deletion_deliveries WHERE id = $1;

-- name: AccountDeletionDelivery :one
SELECT sqlc.embed(d), e.issuer, e.stage, e.completed_at
FROM account_deletion_deliveries e JOIN account_deletions d ON d.id = e.deletion_id
WHERE e.id = $1;

-- name: AccountDeletionDeliveryEarlierPending :one
SELECT EXISTS (
    SELECT 1 FROM account_deletion_deliveries
    WHERE user_id = sqlc.arg(user_id) AND issuer = sqlc.arg(issuer) AND id < sqlc.arg(id) AND completed_at IS NULL
);

-- name: AccountDeletionDeliveryComplete :execrows
UPDATE account_deletion_deliveries SET completed_at = statement_timestamp() WHERE id = $1 AND completed_at IS NULL;

-- name: AccountDeletionHardDeliveriesPending :one
SELECT EXISTS (
    SELECT 1 FROM account_deletion_deliveries WHERE deletion_id = $1 AND stage = 'hard' AND completed_at IS NULL
);

-- name: AccountDeliveryFleetInsert :exec
INSERT INTO account_delivery_fleets (issuer, river_schema) VALUES ($1, $2) ON CONFLICT (issuer) DO NOTHING;

-- name: AccountDeliveryFleetSchemaForUpdate :one
SELECT river_schema FROM account_delivery_fleets WHERE issuer = $1 FOR UPDATE;

-- name: AccountDeliveryFleetSchemaForShare :one
SELECT river_schema FROM account_delivery_fleets WHERE issuer = $1 FOR SHARE;

-- name: AccountDeliveryFleetBusy :one
-- Whether the issuer still has lifecycle work in its current fleet.
SELECT (
    EXISTS (SELECT 1 FROM account_deletion_deliveries WHERE issuer = sqlc.arg(issuer)::text AND completed_at IS NULL)
    OR EXISTS (SELECT 1 FROM account_deletions WHERE state IN ('deleted', 'finalizing') AND sqlc.arg(issuer)::text = ANY(recipients))
    OR EXISTS (SELECT 1 FROM account_events WHERE issuer = sqlc.arg(issuer)::text)
)::boolean AS busy;

-- name: AccountDeliveryFleetSetSchema :exec
UPDATE account_delivery_fleets SET river_schema = sqlc.arg(river_schema) WHERE issuer = sqlc.arg(issuer);

-- name: AccountDeliveryFleetSetEvents :exec
UPDATE account_delivery_fleets SET events = sqlc.arg(events) WHERE issuer = sqlc.arg(issuer) AND events <> sqlc.arg(events);

-- name: AccountDeliveryFleetsUnbound :one
-- The issuers, sorted, with no fleet bound yet.
SELECT coalesce(array_agg(i ORDER BY i), '{}')::text[] AS unbound
FROM unnest(sqlc.arg(issuers)::text[]) i
WHERE NOT EXISTS (SELECT 1 FROM account_delivery_fleets f WHERE f.issuer = i);
