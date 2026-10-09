-- SCIM provisioning (Config.Provisioning): targets, the outbox the users
-- triggers write, and what each target holds.

-- name: ProvisioningTargetRegister :exec
INSERT INTO provisioning_targets (issuer, name) VALUES (sqlc.arg(issuer), sqlc.arg(name))
ON CONFLICT DO NOTHING;

-- name: ProvisioningTargetsPrune :many
-- The issuer's targets no longer configured, deleted with their outbox.
DELETE FROM provisioning_targets
WHERE issuer = sqlc.arg(issuer) AND NOT (name = ANY(sqlc.arg(names)::text[]))
RETURNING name;

-- name: ProvisioningTarget :one
SELECT * FROM provisioning_targets WHERE issuer = sqlc.arg(issuer) AND name = sqlc.arg(name);

-- name: ProvisioningTargetStatuses :many
SELECT t.name, t.synced_at, t.reconciled_at, t.last_success_at, t.failing_since, t.last_error,
       (SELECT count(DISTINCT c.user_id) FROM provisioning_changes c WHERE c.issuer = t.issuer AND c.target = t.name)::bigint AS backlog
FROM provisioning_targets t
WHERE t.issuer = sqlc.arg(issuer) AND t.name = ANY(sqlc.arg(names)::text[])
ORDER BY t.name;

-- name: ProvisioningSyncPage :many
-- The initial sync's next page: every account after sync_after, in id order.
INSERT INTO provisioning_changes (issuer, target, user_id)
SELECT sqlc.arg(issuer)::text, sqlc.arg(target)::text, u.id FROM users u
WHERE sqlc.narg(after)::uuid IS NULL OR u.id > sqlc.narg(after)::uuid
ORDER BY u.id
LIMIT sqlc.arg(page_size)
RETURNING user_id;

-- name: ProvisioningSyncAdvance :exec
UPDATE provisioning_targets SET sync_after = sqlc.arg(after)::uuid
WHERE issuer = sqlc.arg(issuer) AND name = sqlc.arg(name);

-- name: ProvisioningSyncDone :exec
UPDATE provisioning_targets SET synced_at = statement_timestamp(), reconciled_at = statement_timestamp()
WHERE issuer = sqlc.arg(issuer) AND name = sqlc.arg(name);

-- name: ProvisioningDueWindow :many
-- The oldest due changes: one batch's users.
SELECT user_id FROM provisioning_changes
WHERE issuer = sqlc.arg(issuer) AND target = sqlc.arg(target) AND due_at <= sqlc.arg(as_of)
ORDER BY due_at, id
LIMIT sqlc.arg(max_rows);

-- name: ProvisioningPendingThrough :many
-- Each user's newest due change: what sending its state now covers.
SELECT user_id, max(id)::bigint AS through
FROM provisioning_changes
WHERE issuer = sqlc.arg(issuer) AND target = sqlc.arg(target) AND user_id = ANY(sqlc.arg(users)::uuid[])
  AND due_at <= sqlc.arg(as_of)
GROUP BY user_id;

-- name: ProvisioningAccept :exec
-- The target accepted these users' state: their changes up to through are
-- delivered, retries waiting out a backoff included; a change scheduled for
-- later (a ban's end) stays.
DELETE FROM provisioning_changes c
USING unnest(sqlc.arg(users)::uuid[], sqlc.arg(throughs)::bigint[]) AS a(user_id, through)
WHERE c.issuer = sqlc.arg(issuer) AND c.target = sqlc.arg(target)
  AND c.user_id = a.user_id AND c.id <= a.through AND (c.due_at <= sqlc.arg(as_of) OR c.attempts > 0);

-- name: ProvisioningRetry :exec
-- The target refused a user's state: retry it after a backoff doubling from
-- base_seconds up to max_seconds.
UPDATE provisioning_changes
SET attempts = attempts + 1, last_error = sqlc.arg(last_error),
    due_at = sqlc.arg(as_of)::timestamptz + make_interval(secs => least(sqlc.arg(base_seconds)::float8 * power(2, least(attempts, 30)), sqlc.arg(max_seconds)::float8))
WHERE issuer = sqlc.arg(issuer) AND target = sqlc.arg(target) AND user_id = sqlc.arg(user_id)
  AND id <= sqlc.arg(through) AND due_at <= sqlc.arg(as_of);

-- name: ProvisioningSchedule :exec
-- A change due at due_at (a temporary ban's end), unless one is queued.
INSERT INTO provisioning_changes (issuer, target, user_id, due_at)
SELECT sqlc.arg(issuer), sqlc.arg(target), sqlc.arg(user_id), sqlc.arg(due_at)
WHERE NOT EXISTS (
  SELECT 1 FROM provisioning_changes
  WHERE issuer = sqlc.arg(issuer) AND target = sqlc.arg(target) AND user_id = sqlc.arg(user_id) AND due_at = sqlc.arg(due_at)
);

-- name: ProvisioningEnqueue :exec
INSERT INTO provisioning_changes (issuer, target, user_id)
SELECT sqlc.arg(issuer)::text, sqlc.arg(target)::text, u FROM unnest(sqlc.arg(users)::uuid[]) AS u;

-- name: ProvisioningResources :many
SELECT * FROM provisioning_resources
WHERE issuer = sqlc.arg(issuer) AND target = sqlc.arg(target) AND user_id = ANY(sqlc.arg(users)::uuid[]);

-- name: ProvisioningResourceUpsert :exec
INSERT INTO provisioning_resources (issuer, target, user_id, remote_id, state_digest)
VALUES (sqlc.arg(issuer), sqlc.arg(target), sqlc.arg(user_id), sqlc.arg(remote_id), sqlc.arg(state_digest))
ON CONFLICT (issuer, target, user_id) DO UPDATE
SET remote_id = EXCLUDED.remote_id, state_digest = EXCLUDED.state_digest, synced_at = statement_timestamp();

-- name: ProvisioningResourceDelete :exec
DELETE FROM provisioning_resources
WHERE issuer = sqlc.arg(issuer) AND target = sqlc.arg(target) AND user_id = sqlc.arg(user_id);

-- name: ProvisioningResourcesSeen :exec
-- Reconciliation found these resources at the target; an empty digest makes
-- the next batch replace a drifted one.
INSERT INTO provisioning_resources (issuer, target, user_id, remote_id, state_digest, seen_at)
SELECT sqlc.arg(issuer)::text, sqlc.arg(target)::text, s.user_id, s.remote_id, s.state_digest, sqlc.arg(as_of)::timestamptz
FROM unnest(sqlc.arg(users)::uuid[], sqlc.arg(remote_ids)::text[], sqlc.arg(digests)::text[]) AS s(user_id, remote_id, state_digest)
ON CONFLICT (issuer, target, user_id) DO UPDATE
SET seen_at = EXCLUDED.seen_at, remote_id = EXCLUDED.remote_id, state_digest = EXCLUDED.state_digest;

-- name: ProvisioningReconcileMissing :exec
-- Resources reconciliation did not find at the target are created again.
WITH gone AS (
  DELETE FROM provisioning_resources
  WHERE issuer = sqlc.arg(issuer) AND target = sqlc.arg(target)
    AND (seen_at IS NULL OR seen_at < sqlc.arg(as_of)) AND synced_at < sqlc.arg(as_of)
  RETURNING user_id
)
INSERT INTO provisioning_changes (issuer, target, user_id)
SELECT sqlc.arg(issuer)::text, sqlc.arg(target)::text, user_id FROM gone;

-- name: ProvisioningReconcileUnlinked :exec
-- Accounts the target holds no resource for, and none is pending for.
INSERT INTO provisioning_changes (issuer, target, user_id)
SELECT sqlc.arg(issuer)::text, sqlc.arg(target)::text, u.id FROM users u
WHERE NOT EXISTS (SELECT 1 FROM provisioning_resources r WHERE r.issuer = sqlc.arg(issuer) AND r.target = sqlc.arg(target) AND r.user_id = u.id)
  AND NOT EXISTS (SELECT 1 FROM provisioning_changes c WHERE c.issuer = sqlc.arg(issuer) AND c.target = sqlc.arg(target) AND c.user_id = u.id);

-- name: ProvisioningReconciled :exec
UPDATE provisioning_targets SET reconciled_at = sqlc.arg(as_of)
WHERE issuer = sqlc.arg(issuer) AND name = sqlc.arg(name);

-- name: ProvisioningTargetFailed :exec
-- The target could not be reached, or refused a batch: nothing was sent,
-- and the next run waits until retry_at.
UPDATE provisioning_targets
SET failures = failures + 1, failing_since = COALESCE(failing_since, statement_timestamp()),
    retry_at = sqlc.arg(retry_at), last_error = sqlc.arg(last_error)
WHERE issuer = sqlc.arg(issuer) AND name = sqlc.arg(name);

-- name: ProvisioningTargetRan :exec
-- A run reached the target. Clean: it accepted everything sent. The target
-- stays failing while any user's change waits for a retry.
UPDATE provisioning_targets t
SET failures = 0, retry_at = NULL,
    last_success_at = CASE WHEN sqlc.arg(clean)::boolean THEN statement_timestamp() ELSE t.last_success_at END,
    failing_since = CASE
      WHEN sqlc.arg(clean)::boolean AND NOT EXISTS (
        SELECT 1 FROM provisioning_changes c WHERE c.issuer = t.issuer AND c.target = t.name AND c.attempts > 0)
      THEN NULL ELSE COALESCE(t.failing_since, statement_timestamp()) END,
    last_error = CASE
      WHEN sqlc.arg(clean)::boolean AND NOT EXISTS (
        SELECT 1 FROM provisioning_changes c WHERE c.issuer = t.issuer AND c.target = t.name AND c.attempts > 0)
      THEN NULL ELSE COALESCE(sqlc.narg(last_error), t.last_error) END
WHERE t.issuer = sqlc.arg(issuer) AND t.name = sqlc.arg(name);
