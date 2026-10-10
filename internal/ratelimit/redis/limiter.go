// Package redislimiter is the Redis-backed sliding-window rate limiter over
// ratelimit.Limit buckets, shared by every replica. While Redis fails it
// limits in process instead.
package redislimiter

import (
	"context"
	"fmt"
	"maps"
	"strconv"
	"time"

	"github.com/open-rails/authkit/internal/ratelimit"
	memorylimiter "github.com/open-rails/authkit/internal/ratelimit/memory"
	"github.com/open-rails/authkit/internal/redisfallback"
	"github.com/redis/go-redis/v9"
)

// Limiter is a Redis sliding-window limiter using ZSETs, with an in-process
// fallback holding the same limits.
type Limiter struct {
	rdb      redis.UniversalClient
	limits   map[string]ratelimit.Limit
	prefix   string
	fallback *memorylimiter.Limiter
	gate     *redisfallback.Gate
}

// New builds a Redis sliding-window limiter whose keys live under prefix (the
// deployment namespace, #307): <prefix><key>:<bucket>.
func New(rdb redis.UniversalClient, limits map[string]ratelimit.Limit, prefix string) (*Limiter, error) {
	if rdb == nil {
		return nil, fmt.Errorf("ratelimit: Redis client required")
	}
	fallback, err := memorylimiter.New(limits)
	if err != nil {
		return nil, err
	}
	return &Limiter{rdb: rdb, limits: maps.Clone(limits), prefix: prefix, fallback: fallback, gate: redisfallback.New(
		"authkit: Redis rate limiting failed; each process limits on its own until Redis recovers",
		"authkit: Redis rate limiting recovered; budgets are shared again")}, nil
}

// StartCleanup sweeps the fallback's idle buckets until ctx is cancelled.
func (l *Limiter) StartCleanup(ctx context.Context, interval time.Duration) {
	l.fallback.StartCleanup(ctx, interval)
}

// Allow decides in Redis. While Redis fails it decides in process with the
// same limits (redisfallback).
func (l *Limiter) Allow(ctx context.Context, bucket, key string) ratelimit.Result {
	if result, ok := redisfallback.Run(ctx, l.gate, func(ctx context.Context) (ratelimit.Result, error) {
		return l.shared(ctx, bucket, key)
	}); ok {
		return result
	}
	return l.fallback.Allow(ctx, bucket, key)
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

// shared decides in Redis.
func (l *Limiter) shared(ctx context.Context, bucket, key string) (ratelimit.Result, error) {
	lim, _ := ratelimit.LookupLimit(l.limits, bucket)
	now := time.Now()
	nowMs := now.UnixMilli()
	start := nowMs - lim.Window.Milliseconds()
	limitKey := l.prefix + key + ":" + bucket
	member := fmt.Sprintf("%d:%d", nowMs, now.UnixNano())

	vals, err := allowScript.Run(ctx, l.rdb, []string{limitKey},
		nowMs, start, lim.Limit, lim.Window.Milliseconds(), lim.Cooldown.Milliseconds(), member).Slice()
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
