-- Session-event history queries (#245). Best-effort
-- append-only log: sign-ins, revocations, password changes. Retention-pruned.

-- name: SessionEventInsert :exec
INSERT INTO session_events (occurred_at, issuer, user_id, session_id, event, method, reason, ip_addr, user_agent)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9);

-- name: SessionEventsPruneBatch :execrows
-- One bounded retention batch: delete up to batch_size rows older than cutoff,
-- walking the occurred_at index. Callers loop until a short batch — never an
-- unbounded single DELETE.
DELETE FROM session_events
WHERE id IN (
    SELECT id FROM session_events
    WHERE occurred_at < sqlc.arg(cutoff)::timestamptz
    ORDER BY occurred_at
    LIMIT sqlc.arg(batch_size)::bigint
);
