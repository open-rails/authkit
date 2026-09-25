-- Each operation is one statement. Expiry always uses the database clock, so
-- replicas with skewed clocks agree on what is live.

-- name: EphemeralGet :one
SELECT value FROM ephemeral_kv
WHERE key = sqlc.arg(key) AND expires_at > now();

-- name: EphemeralSet :exec
INSERT INTO ephemeral_kv (key, value, expires_at)
VALUES (sqlc.arg(key), sqlc.arg(value), now() + sqlc.arg(ttl_us)::bigint * interval '1 microsecond')
ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value, expires_at = EXCLUDED.expires_at;

-- name: EphemeralDelete :exec
DELETE FROM ephemeral_kv WHERE key = sqlc.arg(key);

-- name: EphemeralConsume :one
DELETE FROM ephemeral_kv
WHERE key = sqlc.arg(key) AND expires_at > now()
RETURNING value;

-- name: EphemeralCompareAndConsume :execrows
DELETE FROM ephemeral_kv
WHERE key = sqlc.arg(key) AND value = sqlc.arg(expected)
  AND expires_at > now();

-- name: EphemeralIncr :one
-- The TTL is set when the counter starts and never extended; an expired
-- counter restarts at 1.
INSERT INTO ephemeral_kv AS kv (key, value, expires_at)
VALUES (sqlc.arg(key), '\x31'::bytea, now() + sqlc.arg(ttl_us)::bigint * interval '1 microsecond')
ON CONFLICT (key) DO UPDATE SET
  value = CASE WHEN kv.expires_at <= now() THEN EXCLUDED.value
    ELSE convert_to((convert_from(kv.value, 'UTF8')::bigint + 1)::text, 'UTF8') END,
  expires_at = CASE WHEN kv.expires_at <= now() THEN EXCLUDED.expires_at
    ELSE kv.expires_at END
RETURNING convert_from(value, 'UTF8')::bigint AS n;

-- name: EphemeralDeleteExpired :execrows
DELETE FROM ephemeral_kv
WHERE key IN (
  SELECT e.key FROM ephemeral_kv e
  WHERE e.expires_at <= now()
  ORDER BY e.expires_at LIMIT sqlc.arg(batch_size) FOR UPDATE SKIP LOCKED
) AND expires_at <= now();
