package memorylimiter

import (
	"fmt"
	"sync"
	"time"
)

// Limit defines window and max count for a bucket.
type Limit struct {
	Limit    int
	Window   time.Duration
	Cooldown time.Duration
}

type bucketState struct {
	// timestamps holds request times in Unix ms, newest last.
	timestamps []int64
}

// Limiter is an in-memory sliding-window rate limiter.
// It is intended as a single-node fallback when Redis is unavailable.
type Limiter struct {
	mu      sync.Mutex
	limits  map[string]Limit
	buckets map[string]*bucketState
}

// New constructs a new in-memory limiter with the provided per-bucket limits.
func New(limits map[string]Limit) *Limiter {
	if limits == nil {
		limits = map[string]Limit{}
	}
	return &Limiter{
		limits:  limits,
		buckets: make(map[string]*bucketState),
	}
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

// AllowNamed matches the auth adapter's RateLimiter interface.
// It uses a simple sliding window over the configured duration, pruning
// expired entries on each call and removing empty buckets to avoid unbounded
// memory growth.
func (l *Limiter) AllowNamed(bucket, key string) (bool, error) {
	allowed, _, err := l.AllowNamedWithRetryAfter(bucket, key)
	return allowed, err
}

func (l *Limiter) AllowNamedWithRetryAfter(bucket, key string) (bool, time.Duration, error) {
	if l == nil {
		return true, 0, nil
	}
	if bucket == "" || key == "" {
		return false, 0, fmt.Errorf("bucket and key required")
	}

	lim, _ := l.get(bucket)
	nowMs := time.Now().UnixNano() / 1e6
	windowStart := nowMs - lim.Window.Milliseconds()
	limitKey := fmt.Sprintf("%s:%s", key, bucket)

	l.mu.Lock()
	defer l.mu.Unlock()

	b, ok := l.buckets[limitKey]
	if !ok {
		b = &bucketState{}
		l.buckets[limitKey] = b
	}

	// Prune timestamps outside the window.
	ts := b.timestamps
	pruneIdx := 0
	for pruneIdx < len(ts) && ts[pruneIdx] < windowStart {
		pruneIdx++
	}
	if pruneIdx > 0 {
		ts = ts[pruneIdx:]
	}

	var retryAfter time.Duration
	if lim.Cooldown > 0 && len(ts) > 0 {
		nextAllowedMs := ts[len(ts)-1] + lim.Cooldown.Milliseconds()
		if nowMs < nextAllowedMs {
			retryAfter = time.Duration(nextAllowedMs-nowMs) * time.Millisecond
		}
	}

	if len(ts) >= lim.Limit {
		windowRetryAfter := time.Duration(ts[0]+lim.Window.Milliseconds()-nowMs) * time.Millisecond
		if windowRetryAfter < 0 {
			windowRetryAfter = 0
		}
		if windowRetryAfter > retryAfter {
			retryAfter = windowRetryAfter
		}
	}

	if retryAfter > 0 {
		// Deny without recording this attempt.
		b.timestamps = ts
		return false, retryAfter, nil
	}

	// Record this request and allow.
	ts = append(ts, nowMs)
	b.timestamps = ts

	// If all timestamps fell out of the window (edge case), drop the bucket.
	if len(ts) == 0 {
		delete(l.buckets, limitKey)
	}

	return true, 0, nil
}
