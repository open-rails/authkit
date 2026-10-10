// Package redislimiter is the Redis-backed sliding-window rate limiter over
// ratelimit.Limit buckets, shared by every replica. While Redis fails it
// spends the budgets in its fallback, the PostgreSQL limiter.
package redislimiter

import (
	"context"
	"fmt"
	"log/slog"
	"maps"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/open-rails/authkit/internal/ratelimit"
	"github.com/redis/go-redis/v9"
)

const (
	// commandTimeout bounds what one decision waits on Redis, whatever the
	// client's own timeouts, so an outage costs a request at most this.
	commandTimeout = 250 * time.Millisecond
	// While Redis fails, one request tries it again after a backoff that
	// doubles from minBackoff to maxBackoff; the rest decide in the fallback.
	minBackoff = time.Second
	maxBackoff = 30 * time.Second
)

// Limiter is a Redis sliding-window limiter using ZSETs, with a fallback
// every replica shares holding the same limits.
type Limiter struct {
	rdb      redis.UniversalClient
	limits   map[string]ratelimit.Limit
	prefix   string
	fallback ratelimit.Limiter

	down    atomic.Bool
	mu      sync.Mutex // guards backoff and retryAt
	backoff time.Duration
	retryAt time.Time
}

// New builds a Redis sliding-window limiter whose keys live under prefix (the
// deployment namespace, #307): <prefix><key>:<bucket>. fallback decides while
// Redis fails.
func New(rdb redis.UniversalClient, limits map[string]ratelimit.Limit, prefix string, fallback ratelimit.Limiter) (*Limiter, error) {
	if rdb == nil || fallback == nil {
		return nil, fmt.Errorf("ratelimit: Redis client and fallback required")
	}
	if err := ratelimit.ValidateLimits(limits); err != nil {
		return nil, err
	}
	return &Limiter{rdb: rdb, limits: maps.Clone(limits), prefix: prefix, fallback: fallback}, nil
}

// Allow decides in Redis. When Redis fails it decides in the fallback with
// the same limits, logs once, and lets one request try Redis again after each
// backoff; the first success logs the recovery.
func (l *Limiter) Allow(ctx context.Context, bucket, key string) (ratelimit.Result, error) {
	probe := false
	if l.down.Load() {
		if probe = l.claimProbe(); !probe {
			return l.fallback.Allow(ctx, bucket, key)
		}
	}
	result, err := l.shared(ctx, bucket, key)
	if err == nil {
		l.recovered()
		return result, nil
	}
	if ctx.Err() == nil { // the caller giving up is no outage
		l.failed(err, probe)
	}
	return l.fallback.Allow(ctx, bucket, key)
}

// claimProbe reports whether this request tries Redis again: the first one
// after the backoff.
func (l *Limiter) claimProbe() bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := time.Now()
	if now.Before(l.retryAt) {
		return false
	}
	l.retryAt = now.Add(l.backoff)
	return true
}

func (l *Limiter) failed(err error, probe bool) {
	l.mu.Lock()
	defer l.mu.Unlock()
	switch {
	case !l.down.Load():
		l.backoff = minBackoff
		l.down.Store(true)
		slog.Warn("authkit: Redis rate limiting failed; budgets are spent in PostgreSQL until Redis recovers", "error", err)
	case probe:
		l.backoff = min(2*l.backoff, maxBackoff)
	default:
		return
	}
	l.retryAt = time.Now().Add(l.backoff)
}

func (l *Limiter) recovered() {
	if !l.down.Load() {
		return
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.down.Swap(false) {
		slog.Info("authkit: Redis rate limiting recovered")
	}
}

// allowScript performs the entire sliding-window decision in a single atomic
// server-side step (#217). Previously the count check and the ZAdd were split
// across a pipeline read and a follow-up write, which (a) let concurrent callers
// read the same sub-limit count and both record — over-admitting past the limit
// (TOCTOU) — and (b) cost extra round-trips, including a redundant EXPIRE that
// duplicated the one already in the pipeline. Folding prune + count +
// conditional record + TTL refresh into one script removes both problems while
// keeping the returned ratelimit.Result shape identical.
//
// KEYS[1] = bucket key
// ARGV    = now(ms) start(ms) limit windowMs cooldownMs member
// Returns = { allowed(0|1), count(pre-add), retryAfterMs, reasonCode }
//
//	reasonCode: 0 none, 1 cooldown, 2 limit_exceeded
//
// The cooldown/limit retry-after math mirrors the former Go implementation
// exactly: entry scores are Unix-ms, the oldest entry drives the window reset,
// the newest drives the cooldown, and admission happens only when the combined
// retry-after is zero.
var allowScript = redis.NewScript(`
local key        = KEYS[1]
local now        = tonumber(ARGV[1])
local start      = tonumber(ARGV[2])
local limit      = tonumber(ARGV[3])
local windowMs   = tonumber(ARGV[4])
local cooldownMs = tonumber(ARGV[5])
local member     = ARGV[6]

redis.call('ZREMRANGEBYSCORE', key, 0, start)
local count  = redis.call('ZCARD', key)
local oldest = redis.call('ZRANGE', key, 0, 0, 'WITHSCORES')
local latest = redis.call('ZRANGE', key, -1, -1, 'WITHSCORES')

local retryAfter = 0
local reason = 0

if cooldownMs > 0 and #latest > 0 then
  local nextAllowed = tonumber(latest[2]) + cooldownMs
  if now < nextAllowed then
    retryAfter = nextAllowed - now
    reason = 1
  end
end

if count >= limit then
  local windowRetryAfter = windowMs
  if #oldest > 0 then
    windowRetryAfter = tonumber(oldest[2]) + windowMs - now
    if windowRetryAfter < 0 then
      windowRetryAfter = 0
    end
  end
  if windowRetryAfter > retryAfter then
    retryAfter = windowRetryAfter
    reason = 2
  end
end

local allowed = 0
if retryAfter <= 0 then
  redis.call('ZADD', key, now, member)
  allowed = 1
end
redis.call('PEXPIRE', key, windowMs)

return {allowed, count, retryAfter, reason}
`)

// shared decides in Redis, waiting at most commandTimeout.
func (l *Limiter) shared(ctx context.Context, bucket, key string) (ratelimit.Result, error) {
	lim, _ := ratelimit.LookupLimit(l.limits, bucket)
	now := time.Now()
	nowMs := now.UnixMilli()
	start := nowMs - lim.Window.Milliseconds()
	limitKey := l.prefix + key + ":" + bucket
	member := fmt.Sprintf("%d:%d", nowMs, now.UnixNano())

	ctx, cancel := context.WithTimeout(ctx, commandTimeout)
	defer cancel()
	// The client honors ctx only with ContextTimeoutEnabled, so the wait is
	// bounded here; an abandoned command ends at the client's own timeout.
	reply := make(chan *redis.Cmd, 1)
	go func() {
		reply <- allowScript.Run(ctx, l.rdb, []string{limitKey},
			nowMs, start, lim.Limit, lim.Window.Milliseconds(), lim.Cooldown.Milliseconds(), member)
	}()
	var cmd *redis.Cmd
	select {
	case cmd = <-reply:
	case <-ctx.Done():
		return ratelimit.Result{}, ctx.Err()
	}
	vals, err := cmd.Slice()
	if err != nil {
		return ratelimit.Result{}, err
	}
	if len(vals) < 4 {
		return ratelimit.Result{}, fmt.Errorf("ratelimit: unexpected script result %v", vals)
	}
	allowed := toInt64(vals[0]) == 1
	count := toInt64(vals[1])
	retryAfterMs := toInt64(vals[2])
	reasonCode := toInt64(vals[3])

	if !allowed {
		return ratelimit.Result{
			Allowed:    false,
			RetryAfter: time.Duration(retryAfterMs) * time.Millisecond,
			Reason:     reasonFromCode(reasonCode),
			Limit:      lim.Limit,
			Remaining:  ratelimit.Remaining(lim.Limit, count),
			Window:     lim.Window,
			Cooldown:   lim.Cooldown,
		}, nil
	}
	return ratelimit.Result{
		Allowed:   true,
		Limit:     lim.Limit,
		Remaining: ratelimit.Remaining(lim.Limit, count+1),
		Window:    lim.Window,
		Cooldown:  lim.Cooldown,
	}, nil
}

func reasonFromCode(code int64) string {
	switch code {
	case 1:
		return ratelimit.ReasonCooldown
	case 2:
		return ratelimit.ReasonLimitExceeded
	default:
		return ""
	}
}

// toInt64 coerces the loosely typed elements go-redis returns from a Lua array
// reply (int64, or occasionally a string) into an int64.
func toInt64(v interface{}) int64 {
	switch n := v.(type) {
	case int64:
		return n
	case int:
		return int64(n)
	case string:
		i, _ := strconv.ParseInt(n, 10, 64)
		return i
	default:
		return 0
	}
}
