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
SELECT position, event_id, kind, recorded_at, payload FROM event_log
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
