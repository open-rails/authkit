-- name: EventLogCreateScope :exec
INSERT INTO event_log_scopes(scope) VALUES(sqlc.arg(scope)) ON CONFLICT DO NOTHING;

-- name: EventLogLockScope :one
SELECT position, retained_after FROM event_log_scopes WHERE scope=sqlc.arg(scope) FOR UPDATE;

-- name: EventLogAdvanceScope :exec
UPDATE event_log_scopes SET position=sqlc.arg(position) WHERE scope=sqlc.arg(scope);

-- name: EventLogInsert :exec
INSERT INTO event_log(scope, position, event_id, kind, recorded_at, payload)
VALUES(sqlc.arg(scope), sqlc.arg(position), sqlc.arg(event_id)::uuid,
       sqlc.arg(kind), clock_timestamp(), sqlc.arg(payload)::jsonb);

-- name: EventLogSnapshot :one
SELECT epoch,
       coalesce((SELECT position FROM event_log_scopes WHERE scope=sqlc.arg(scope)), 0)::bigint AS head,
       greatest(
         coalesce((SELECT retained_after FROM event_log_scopes WHERE scope=sqlc.arg(scope)), 0),
         coalesce((SELECT min(position)-1 FROM event_log WHERE scope=sqlc.arg(scope)
                   AND recorded_at >= sqlc.arg(cutoff)),
                  (SELECT position FROM event_log_scopes WHERE scope=sqlc.arg(scope)), 0)
       )::bigint AS retained_after
FROM event_log_instance WHERE singleton;

-- name: EventLogItems :many
SELECT position, event_id, recorded_at, payload FROM event_log
WHERE scope=sqlc.arg(scope) AND position>sqlc.arg(after_position)
  AND recorded_at>=sqlc.arg(cutoff)
  AND (cardinality(sqlc.arg(kinds)::text[])=0 OR kind=ANY(sqlc.arg(kinds)::text[]))
ORDER BY position LIMIT sqlc.arg(page_limit);

-- name: EventLogPosition :one
SELECT event_id FROM event_log WHERE scope=sqlc.arg(scope) AND position=sqlc.arg(position);

-- name: EventLogDueScopes :many
SELECT scope FROM event_log_scopes s
WHERE EXISTS (SELECT 1 FROM event_log e WHERE e.scope=s.scope AND e.recorded_at<sqlc.arg(cutoff))
ORDER BY scope LIMIT 100;

-- name: EventLogPrune :one
WITH chosen AS (
    SELECT position FROM event_log WHERE scope=sqlc.arg(scope)
      AND position<coalesce((SELECT min(position) FROM event_log WHERE scope=sqlc.arg(scope)
                            AND recorded_at>=sqlc.arg(cutoff)), 9223372036854775807)
      AND recorded_at<sqlc.arg(cutoff)
    ORDER BY position LIMIT 5000
), removed AS (
    DELETE FROM event_log WHERE scope=sqlc.arg(scope) AND position IN (SELECT position FROM chosen)
    RETURNING position
)
UPDATE event_log_scopes SET retained_after=greatest(retained_after, coalesce((SELECT max(position) FROM removed), 0))
WHERE scope=sqlc.arg(scope) RETURNING retained_after;
