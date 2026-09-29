-- Durable account and group events (Deps.OnEvent): one account_events row per
-- subscribed issuer, recorded in the change's transaction, deleted on delivery.

-- name: AccountEventFleetsForShare :many
-- The subscribed issuers' fleets, key-share locked until the change commits.
SELECT issuer, river_schema FROM account_delivery_fleets
WHERE events AND issuer = ANY(sqlc.arg(issuers)::text[])
ORDER BY issuer FOR KEY SHARE;

-- name: AccountEventInsert :one
INSERT INTO account_events
    (issuer, subject, event_id, kind, actor_kind, actor_id, user_id, group_id, persona, application_id,
     previous_value, current_value, reason, until)
VALUES
    (sqlc.arg(issuer), sqlc.arg(subject), sqlc.arg(event_id), sqlc.arg(kind), sqlc.arg(actor_kind), sqlc.arg(actor_id),
     sqlc.narg(user_id), sqlc.narg(group_id), sqlc.arg(persona), sqlc.narg(application_id),
     sqlc.arg(previous_value), sqlc.arg(current_value), sqlc.arg(reason), sqlc.narg(until))
RETURNING id;

-- name: AccountEventByID :one
SELECT * FROM account_events WHERE id = $1;

-- name: AccountEventEarlierPending :one
-- Whether an earlier event of the subject is still pending, and the seconds
-- until the latest of their retries.
SELECT (count(*) > 0)::boolean AS blocked,
       COALESCE(EXTRACT(EPOCH FROM max(retry_at) - statement_timestamp()), 0)::float8 AS wait
FROM account_events
WHERE issuer = sqlc.arg(issuer) AND subject = sqlc.arg(subject) AND id < sqlc.arg(id);

-- name: AccountEventRetry :exec
UPDATE account_events
SET attempts = attempts + 1, retry_at = statement_timestamp() + make_interval(secs => sqlc.arg(delay_seconds)::float8)
WHERE id = sqlc.arg(id);

-- name: AccountEventDelete :exec
DELETE FROM account_events WHERE id = $1;
