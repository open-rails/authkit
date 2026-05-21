package redislimiter

import (
	"context"
	"fmt"
	"time"

	"github.com/redis/go-redis/v9"
)

// Limit defines window and max count for a bucket.
type Limit struct {
	Limit    int
	Window   time.Duration
	Cooldown time.Duration
}

// Limiter is a Redis-backed sliding window limiter using ZSETs.
type Limiter struct {
	rdb    *redis.Client
	ctx    context.Context
	limits map[string]Limit
}

func New(rdb *redis.Client, limits map[string]Limit) *Limiter {
	if limits == nil {
		limits = map[string]Limit{}
	}
	return &Limiter{rdb: rdb, ctx: context.Background(), limits: limits}
}

func (l *Limiter) get(bucket string) (Limit, bool) {
	if v, ok := l.limits[bucket]; ok {
		return v, true
	}
	if v, ok := l.limits["default"]; ok {
		return v, true
	}
	return Limit{Limit: 100, Window: time.Minute}, false
}

// AllowNamed matches the auth adapter's internal interface.
func (l *Limiter) AllowNamed(bucket, key string) (bool, error) {
	allowed, _, err := l.AllowNamedWithRetryAfter(bucket, key)
	return allowed, err
}

func (l *Limiter) AllowNamedWithRetryAfter(bucket, key string) (bool, time.Duration, error) {
	if l == nil || l.rdb == nil {
		return true, 0, nil
	}
	if bucket == "" || key == "" {
		return false, 0, fmt.Errorf("bucket and key required")
	}
	lim, _ := l.get(bucket)
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
		return false, 0, err
	}
	count, err := countCmd.Result()
	if err != nil {
		return false, 0, err
	}
	var retryAfter time.Duration
	if latest, err := latestCmd.Result(); err != nil {
		return false, 0, err
	} else if lim.Cooldown > 0 && len(latest) > 0 {
		nextAllowed := int64(latest[0].Score) + lim.Cooldown.Milliseconds()
		if now < nextAllowed {
			retryAfter = time.Duration(nextAllowed-now) * time.Millisecond
		}
	}
	if count >= int64(lim.Limit) {
		oldest, err := oldestCmd.Result()
		if err != nil {
			return false, 0, err
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
		}
	}
	if retryAfter > 0 {
		return false, retryAfter, nil
	}

	member := fmt.Sprintf("%d:%d", now, time.Now().UnixNano())
	if err := l.rdb.ZAdd(l.ctx, limitKey, redis.Z{Score: float64(now), Member: member}).Err(); err != nil {
		return false, 0, err
	}
	_ = l.rdb.Expire(l.ctx, limitKey, lim.Window+time.Second).Err()
	return true, 0, nil
}
