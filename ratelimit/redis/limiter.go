package redislimiter

import (
	"context"
	"fmt"
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

	pipe := l.rdb.TxPipeline()
	pipe.ZRemRangeByScore(l.ctx, limitKey, "0", fmt.Sprintf("%d", start))
	oldestCmd := pipe.ZRangeWithScores(l.ctx, limitKey, 0, 0)
	latestCmd := pipe.ZRevRangeWithScores(l.ctx, limitKey, 0, 0)
	countCmd := pipe.ZCard(l.ctx, limitKey)
	pipe.Expire(l.ctx, limitKey, lim.Window+time.Second)
	if _, err := pipe.Exec(l.ctx); err != nil {
		return ratelimit.Result{}, err
	}
	count, err := countCmd.Result()
	if err != nil {
		return ratelimit.Result{}, err
	}
	var retryAfter time.Duration
	var retryReason string
	if latest, err := latestCmd.Result(); err != nil {
		return ratelimit.Result{}, err
	} else if lim.Cooldown > 0 && len(latest) > 0 {
		nextAllowed := int64(latest[0].Score) + lim.Cooldown.Milliseconds()
		if now < nextAllowed {
			retryAfter = time.Duration(nextAllowed-now) * time.Millisecond
			retryReason = ratelimit.ReasonCooldown
		}
	}
	if count >= int64(lim.Limit) {
		oldest, err := oldestCmd.Result()
		if err != nil {
			return ratelimit.Result{}, err
		}
		windowRetryAfter := time.Duration(lim.Window.Milliseconds()) * time.Millisecond
		if len(oldest) > 0 {
			windowRetryAfter = time.Duration(int64(oldest[0].Score)+lim.Window.Milliseconds()-now) * time.Millisecond
			if windowRetryAfter < 0 {
				windowRetryAfter = 0
			}
		}
		if windowRetryAfter > retryAfter {
			retryAfter = windowRetryAfter
			retryReason = ratelimit.ReasonLimitExceeded
		}
	}
	if retryAfter > 0 {
		return ratelimit.Result{
			Allowed:    false,
			RetryAfter: retryAfter,
			Reason:     retryReason,
			Limit:      lim.Limit,
			Remaining:  ratelimit.Remaining(lim.Limit, int(count)),
			Window:     lim.Window,
			Cooldown:   lim.Cooldown,
		}, nil
	}

	member := fmt.Sprintf("%d:%d", now, time.Now().UnixNano())
	if err := l.rdb.ZAdd(l.ctx, limitKey, redis.Z{Score: float64(now), Member: member}).Err(); err != nil {
		return ratelimit.Result{}, err
	}
	_ = l.rdb.Expire(l.ctx, limitKey, lim.Window+time.Second).Err()
	return ratelimit.Result{
		Allowed:   true,
		Limit:     lim.Limit,
		Remaining: ratelimit.Remaining(lim.Limit, int(count)+1),
		Window:    lim.Window,
		Cooldown:  lim.Cooldown,
	}, nil
}
