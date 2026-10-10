// Package memorylimiter is the in-process sliding-window rate limiter over
// ratelimit.Limit buckets: AuthKit's limiter without Redis, and the Redis
// limiter's fallback.
package memorylimiter

import (
	"context"
	"maps"
	"sync"
	"time"

	"github.com/open-rails/authkit/internal/ratelimit"
)

type bucketState struct {
	// timestamps holds request times in Unix ms, newest last.
	timestamps []int64
	// windowMs is the retention window (in ms) for this bucket, recorded on the
	// most recent access. It lets a background sweep evict the bucket once all
	// of its timestamps have aged out, without re-deriving the limit from the
	// composite map key.
	windowMs int64
}

// maxBuckets caps distinct (key, bucket) states held in memory (#305).
const maxBuckets = 100_000

// Limiter is an in-process sliding-window rate limiter.
type Limiter struct {
	mu      sync.Mutex
	limits  map[string]ratelimit.Limit
	buckets map[string]*bucketState
}

// New constructs a new in-memory limiter with the provided per-bucket limits.
func New(limits map[string]ratelimit.Limit) (*Limiter, error) {
	if err := ratelimit.ValidateLimits(limits); err != nil {
		return nil, err
	}
	return &Limiter{limits: maps.Clone(limits), buckets: make(map[string]*bucketState)}, nil
}

// Allow uses a sliding window over the bucket's duration, pruning the
// touched bucket's expired entries. Buckets whose keys go idle are reclaimed
// only by Cleanup, so StartCleanup must run.
func (l *Limiter) Allow(_ context.Context, bucket, key string) ratelimit.Result {
	lim, _ := ratelimit.LookupLimit(l.limits, bucket)
	nowMs := time.Now().UnixMilli()
	windowStart := nowMs - lim.Window.Milliseconds()
	limitKey := key + ":" + bucket

	l.mu.Lock()
	defer l.mu.Unlock()

	b, ok := l.buckets[limitKey]
	if !ok {
		if len(l.buckets) >= maxBuckets && l.cleanupLocked(nowMs) >= maxBuckets {
			return ratelimit.Result{
				Allowed: false, RetryAfter: lim.Window, Reason: ratelimit.ReasonLimitExceeded,
				Limit: lim.Limit, Window: lim.Window, Cooldown: lim.Cooldown,
			}
		}
		b = &bucketState{}
		l.buckets[limitKey] = b
	}
	b.windowMs = lim.Window.Milliseconds()

	// Prune timestamps outside the window.
	ts := b.timestamps
	pruneIdx := 0
	for pruneIdx < len(ts) && ts[pruneIdx] <= windowStart {
		pruneIdx++
	}
	if pruneIdx > 0 {
		ts = ts[pruneIdx:]
	}

	var retryAfter time.Duration
	var retryReason string
	if lim.Cooldown > 0 && len(ts) > 0 {
		nextAllowedMs := ts[len(ts)-1] + lim.Cooldown.Milliseconds()
		if nowMs < nextAllowedMs {
			retryAfter = time.Duration(nextAllowedMs-nowMs) * time.Millisecond
			retryReason = ratelimit.ReasonCooldown
		}
	}

	if len(ts) >= lim.Limit {
		windowRetryAfter := time.Duration(ts[0]+lim.Window.Milliseconds()-nowMs) * time.Millisecond
		if windowRetryAfter < 0 {
			windowRetryAfter = 0
		}
		if windowRetryAfter > retryAfter {
			retryAfter = windowRetryAfter
			retryReason = ratelimit.ReasonLimitExceeded
		}
	}

	if retryAfter > 0 {
		// Deny without recording this attempt.
		b.timestamps = ts
		return ratelimit.Result{
			Allowed:    false,
			RetryAfter: retryAfter,
			Reason:     retryReason,
			Limit:      lim.Limit,
			Remaining:  ratelimit.Remaining(lim.Limit, int64(len(ts))),
			Window:     lim.Window,
			Cooldown:   lim.Cooldown,
		}
	}

	// Record this request and allow. (ts is non-empty here, so there is no
	// empty-bucket case to drop on this path; idle buckets are reclaimed by
	// Cleanup instead.)
	ts = append(ts, nowMs)
	b.timestamps = ts

	return ratelimit.Result{
		Allowed:   true,
		Limit:     lim.Limit,
		Remaining: ratelimit.Remaining(lim.Limit, int64(len(ts))),
		Window:    lim.Window,
		Cooldown:  lim.Cooldown,
	}
}

// Cleanup prunes expired timestamps from every bucket and deletes buckets that
// have no live timestamps left, then returns the number of buckets still
// retained. It is safe to call concurrently with Allow and is the
// mechanism that bounds memory when the limiter is keyed on a high-cardinality,
// attacker-influenced dimension (per-IP, per-identifier): without it, every
// distinct key leaves behind a bucket that is never revisited.
func (l *Limiter) Cleanup() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.cleanupLocked(time.Now().UnixMilli())
}

func (l *Limiter) cleanupLocked(nowMs int64) int {
	for k, b := range l.buckets {
		if b == nil {
			delete(l.buckets, k)
			continue
		}
		windowStart := nowMs - b.windowMs
		ts := b.timestamps
		pruneIdx := 0
		for pruneIdx < len(ts) && ts[pruneIdx] <= windowStart {
			pruneIdx++
		}
		if pruneIdx > 0 {
			ts = ts[pruneIdx:]
		}
		if len(ts) == 0 {
			delete(l.buckets, k)
			continue
		}
		// Re-slice into a fresh backing array so a long-lived bucket that has
		// mostly aged out doesn't retain the original (larger) array.
		trimmed := make([]int64, len(ts))
		copy(trimmed, ts)
		b.timestamps = trimmed
	}
	return len(l.buckets)
}

// StartCleanup runs Cleanup on the given interval until ctx is cancelled. It
// returns immediately, spawning a single background goroutine; cancel ctx to
// stop it. A non-positive interval is treated as a no-op (returns without
// starting a goroutine) so misconfiguration can't spin a hot loop.
func (l *Limiter) StartCleanup(ctx context.Context, interval time.Duration) {
	if interval <= 0 {
		return
	}
	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				l.Cleanup()
			}
		}
	}()
}
