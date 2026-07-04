-- Session-event history queries (authcore/session_events.go, #245). Best-effort
-- append-only log: sign-ins, revocations, password changes. Retention-pruned.

-- name: SessionEventInsert :exec
INSERT INTO profiles.session_events (occurred_at, issuer, user_id, session_id, event, method, reason, ip_addr, user_agent)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9);

-- name: SessionEventsListByUser :many
-- Per-user history, newest-first. An empty events array means all event types.
SELECT occurred_at, issuer, user_id, session_id, event, method, reason, ip_addr, user_agent
FROM profiles.session_events
WHERE user_id = sqlc.arg(user_id)
  AND (cardinality(sqlc.arg(events)::text[]) = 0 OR event = ANY(sqlc.arg(events)::text[]))
ORDER BY occurred_at DESC
LIMIT sqlc.arg(row_limit);

-- name: SessionEventsPruneBatch :execrows
-- One bounded retention batch: delete up to batch_size rows older than cutoff,
-- walking the occurred_at index. Callers loop until a short batch — never an
-- unbounded single DELETE.
DELETE FROM profiles.session_events
WHERE id IN (
    SELECT id FROM profiles.session_events
    WHERE occurred_at < sqlc.arg(cutoff)::timestamptz
    ORDER BY occurred_at
    LIMIT sqlc.arg(batch_size)::bigint
);
