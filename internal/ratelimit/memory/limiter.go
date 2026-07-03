package memorylimiter

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/open-rails/authkit/ratelimit"
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

// Limiter is an in-memory sliding-window rate limiter.
// It is intended as a single-node fallback when Redis is unavailable.
type Limiter struct {
	mu      sync.Mutex
	limits  map[string]ratelimit.Limit
	buckets map[string]*bucketState
}

// New constructs a new in-memory limiter with the provided per-bucket limits.
func New(limits map[string]ratelimit.Limit) *Limiter {
	if limits == nil {
		limits = map[string]ratelimit.Limit{}
	}
	return &Limiter{
		limits:  limits,
		buckets: make(map[string]*bucketState),
	}
}

// AllowNamed matches the auth adapter's RateLimiter interface.
// It uses a simple sliding window over the configured duration, pruning
// expired entries for the touched bucket on each call.
//
// Note that per-call pruning only ever touches buckets that are still being
// hit; buckets for keys that go idle (e.g. a one-off request from an IP that
// never returns) are never revisited and would otherwise live forever. Hosts
// exposing this limiter on attacker-influenced keys (per-IP, per-identifier)
// should run StartCleanup so idle buckets are reclaimed. See Cleanup.
func (l *Limiter) AllowNamed(bucket, key string) (bool, error) {
	result, err := l.AllowNamedResult(bucket, key)
	return result.Allowed, err
}

func (l *Limiter) AllowNamedResult(bucket, key string) (ratelimit.Result, error) {
	if l == nil {
		return ratelimit.Result{Allowed: true}, nil
	}
	if bucket == "" || key == "" {
		return ratelimit.Result{}, fmt.Errorf("bucket and key required")
	}

	lim, _ := ratelimit.LookupLimit(l.limits, bucket)
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
	b.windowMs = lim.Window.Milliseconds()

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
	var retryReason string
	if lim.Cooldown > 0 && len(ts) > 0 {
		nextAllowedMs := ts[len(ts)-1] + lim.Cooldown.Milliseconds()
		if nowMs < nextAllowedMs {
			retryAfter = time.Duration(nextAllowedMs-nowMs) * time.Millisecond
			retryReason = ratelimit.ReasonCooldown
		}
	}

	// Guard Limit > 0: a bucket with Limit <= 0 has no positive threshold, so
	// len(ts) >= lim.Limit would be true even for an empty slice and ts[0] would
	// panic on the empty backing array (#198). Skipping the check leaves the
	// window-exceeded branch inactive for such buckets.
	if lim.Limit > 0 && len(ts) >= lim.Limit {
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
			Remaining:  ratelimit.Remaining(lim.Limit, len(ts)),
			Window:     lim.Window,
			Cooldown:   lim.Cooldown,
		}, nil
	}

	// Record this request and allow. (ts is non-empty here, so there is no
	// empty-bucket case to drop on this path; idle buckets are reclaimed by
	// Cleanup instead.)
	ts = append(ts, nowMs)
	b.timestamps = ts

	return ratelimit.Result{
		Allowed:   true,
		Limit:     lim.Limit,
		Remaining: ratelimit.Remaining(lim.Limit, len(ts)),
		Window:    lim.Window,
		Cooldown:  lim.Cooldown,
	}, nil
}

// Cleanup prunes expired timestamps from every bucket and deletes buckets that
// have no live timestamps left, then returns the number of buckets still
// retained. It is safe to call concurrently with AllowNamed* and is the
// mechanism that bounds memory when the limiter is keyed on a high-cardinality,
// attacker-influenced dimension (per-IP, per-identifier): without it, every
// distinct key leaves behind a bucket that is never revisited.
func (l *Limiter) Cleanup() int {
	if l == nil {
		return 0
	}
	nowMs := time.Now().UnixNano() / 1e6

	l.mu.Lock()
	defer l.mu.Unlock()

	for k, b := range l.buckets {
		if b == nil {
			delete(l.buckets, k)
			continue
		}
		windowStart := nowMs - b.windowMs
		ts := b.timestamps
		pruneIdx := 0
		for pruneIdx < len(ts) && ts[pruneIdx] < windowStart {
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
	if l == nil || interval <= 0 {
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
