-- Session-event history queries (#245). Best-effort
-- append-only log: sign-ins, revocations, password changes. Retention-pruned.

-- name: SessionEventInsert :exec
INSERT INTO session_events (occurred_at, issuer, user_id, session_id, event, method, reason, ip_addr, user_agent)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9);

-- name: SessionEventImport :one
-- Lock ownership and deletion state through the insert. Native entries keep
-- import_id NULL and are unaffected by the partial unique index.
WITH account AS MATERIALIZED (
    SELECT id, deleted_at FROM users
    WHERE id = sqlc.arg(user_id)::uuid AND tenant_id = sqlc.arg(tenant_id)::uuid
    FOR SHARE
), imported AS (
    INSERT INTO session_events (occurred_at, issuer, user_id, session_id, event, method, reason, ip_addr, user_agent, import_id)
    SELECT sqlc.arg(occurred_at)::timestamptz, sqlc.arg(issuer)::text, id::text, '',
           sqlc.arg(event)::text, sqlc.narg(method)::text, sqlc.narg(reason)::text,
           sqlc.narg(ip_addr)::text, sqlc.narg(user_agent)::text, sqlc.arg(import_id)::text
    FROM account WHERE deleted_at IS NULL
    ON CONFLICT (user_id, import_id) WHERE import_id IS NOT NULL DO NOTHING
    RETURNING id
)
SELECT CASE
    WHEN NOT EXISTS (SELECT 1 FROM account) THEN 'unknown_account'
    WHEN EXISTS (SELECT 1 FROM account WHERE deleted_at IS NOT NULL) THEN 'deleted_account'
    WHEN EXISTS (SELECT 1 FROM imported) THEN 'imported'
    ELSE 'duplicate'
END::text AS outcome;

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

-- name: SessionEventsByUser :many
-- One page of an account's history, newest first, after the (after_at,
-- after_id) keyset cursor when after_at is set; no kinds means every kind.
SELECT * FROM session_events
WHERE user_id = sqlc.arg(user_id)
  AND (cardinality(sqlc.arg(kinds)::text[]) = 0 OR event = ANY(sqlc.arg(kinds)::text[]))
  AND (sqlc.narg(after_at)::timestamptz IS NULL OR (occurred_at, id) < (sqlc.narg(after_at), sqlc.arg(after_id)::bigint))
ORDER BY occurred_at DESC, id DESC
LIMIT sqlc.arg(page_limit)::bigint;
