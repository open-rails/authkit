package redislimiter

import (
	"context"
	"fmt"
	"strconv"
	"time"

	"github.com/open-rails/authkit/ratelimit"
	"github.com/redis/go-redis/v9"
)

// Limiter is a Redis-backed sliding window limiter using ZSETs.
type Limiter struct {
	rdb    *redis.Client
	ctx    context.Context
	limits map[string]ratelimit.Limit
}

func New(rdb *redis.Client, limits map[string]ratelimit.Limit) *Limiter {
	if limits == nil {
		limits = map[string]ratelimit.Limit{}
	}
	return &Limiter{rdb: rdb, ctx: context.Background(), limits: limits}
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
// ARGV    = now(ms) start(ms) limit windowMs cooldownMs expireSec member
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
local expireSec  = tonumber(ARGV[6])
local member     = ARGV[7]

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
redis.call('EXPIRE', key, expireSec)

return {allowed, count, retryAfter, reason}
`)

// AllowNamed matches the auth adapter's internal interface.
func (l *Limiter) AllowNamed(bucket, key string) (bool, error) {
	result, err := l.AllowNamedResult(bucket, key)
	return result.Allowed, err
}

func (l *Limiter) AllowNamedResult(bucket, key string) (ratelimit.Result, error) {
	if l == nil || l.rdb == nil {
		return ratelimit.Result{Allowed: true}, nil
	}
	if bucket == "" || key == "" {
		return ratelimit.Result{}, fmt.Errorf("bucket and key required")
	}
	lim, _ := ratelimit.LookupLimit(l.limits, bucket)
	now := time.Now().UnixNano() / 1e6 // ms
	start := now - lim.Window.Milliseconds()
	limitKey := fmt.Sprintf("%s:%s", key, bucket)
	member := fmt.Sprintf("%d:%d", now, time.Now().UnixNano())
	expireSec := int64((lim.Window + time.Second) / time.Second)

	vals, err := allowScript.Run(l.ctx, l.rdb, []string{limitKey},
		now, start, lim.Limit, lim.Window.Milliseconds(), lim.Cooldown.Milliseconds(), expireSec, member,
	).Slice()
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
			Remaining:  ratelimit.Remaining(lim.Limit, int(count)),
			Window:     lim.Window,
			Cooldown:   lim.Cooldown,
		}, nil
	}
	return ratelimit.Result{
		Allowed:   true,
		Limit:     lim.Limit,
		Remaining: ratelimit.Remaining(lim.Limit, int(count)+1),
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
