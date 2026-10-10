-- name: RateLimitSpend :one
-- Spends one request of key's sliding-window budget in one statement on the
-- database clock, so concurrent callers on every replica decide in turn. A
-- hit lapses window_ms after it; a request is admitted while fewer than
-- max_hits are live and the newest is at least cooldown_ms old, and a refusal
-- records nothing. before is the row the decision read (NULL for a new key).
WITH p AS (
  SELECT floor(extract(epoch FROM clock_timestamp()) * 1000)::bigint AS now_ms,
    sqlc.arg(window_ms)::bigint AS window_ms,
    sqlc.arg(max_hits)::bigint AS max_hits,
    sqlc.arg(cooldown_ms)::bigint AS cooldown_ms
)
INSERT INTO rate_limits AS r (key, hits, expires_at)
SELECT sqlc.arg(key)::text, ARRAY[p.now_ms],
  'epoch'::timestamptz + (p.now_ms + p.window_ms) * interval '1 millisecond'
FROM p
ON CONFLICT (key) DO UPDATE SET (hits, expires_at) = (
  SELECT
    CASE WHEN d.admit THEN l.live || p.now_ms ELSE l.live END,
    CASE WHEN d.admit THEN EXCLUDED.expires_at ELSE r.expires_at END
  FROM p,
    LATERAL (SELECT ARRAY(
      SELECT h FROM unnest(r.hits) AS h WHERE h > p.now_ms - p.window_ms ORDER BY h
    ) AS live) l,
    LATERAL (SELECT cardinality(l.live) < p.max_hits
      AND (p.cooldown_ms = 0 OR cardinality(l.live) = 0
        OR l.live[cardinality(l.live)] + p.cooldown_ms <= p.now_ms) AS admit) d
)
RETURNING (SELECT now_ms FROM p) AS now_ms, old.hits AS before, new.hits AS after;

-- name: RateLimitsDeleteExpired :execrows
DELETE FROM rate_limits
WHERE key IN (
  SELECT l.key FROM rate_limits l
  WHERE l.expires_at <= now()
  ORDER BY l.expires_at LIMIT sqlc.arg(batch_size) FOR UPDATE SKIP LOCKED
) AND expires_at <= now();
