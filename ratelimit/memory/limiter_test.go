package memorylimiter

import (
	"context"
	"testing"
	"time"

	"github.com/open-rails/authkit/ratelimit"
)

func TestCleanupEvictsIdleBuckets(t *testing.T) {
	limiter := New(map[string]ratelimit.Limit{
		"probe": {Limit: 5, Window: 20 * time.Millisecond},
	})

	// Many distinct, one-shot keys — the leak scenario (e.g. per-IP probing).
	for i := 0; i < 100; i++ {
		key := "ip-" + time.Duration(i).String()
		if _, err := limiter.AllowNamed("probe", key); err != nil {
			t.Fatalf("AllowNamed: %v", err)
		}
	}

	limiter.mu.Lock()
	created := len(limiter.buckets)
	limiter.mu.Unlock()
	if created != 100 {
		t.Fatalf("expected 100 buckets after distinct keys, got %d", created)
	}

	// Before timestamps age out, Cleanup must retain the live buckets.
	if got := limiter.Cleanup(); got != 100 {
		t.Fatalf("Cleanup evicted live buckets: retained %d, want 100", got)
	}

	// Let every bucket's window elapse, then sweep.
	time.Sleep(30 * time.Millisecond)
	if got := limiter.Cleanup(); got != 0 {
		t.Fatalf("Cleanup did not reclaim idle buckets: retained %d, want 0", got)
	}
}

func TestCleanupKeepsBucketWithLiveTimestamps(t *testing.T) {
	limiter := New(map[string]ratelimit.Limit{
		"login": {Limit: 5, Window: time.Hour},
	})
	if _, err := limiter.AllowNamed("login", "user"); err != nil {
		t.Fatalf("AllowNamed: %v", err)
	}
	if got := limiter.Cleanup(); got != 1 {
		t.Fatalf("Cleanup dropped a bucket with a live timestamp: retained %d, want 1", got)
	}
}

func TestStartCleanupStopsOnContextCancel(t *testing.T) {
	limiter := New(map[string]ratelimit.Limit{
		"probe": {Limit: 5, Window: 5 * time.Millisecond},
	})
	if _, err := limiter.AllowNamed("probe", "one-shot"); err != nil {
		t.Fatalf("AllowNamed: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	limiter.StartCleanup(ctx, time.Millisecond)
	defer cancel()

	deadline := time.After(time.Second)
	for {
		limiter.mu.Lock()
		n := len(limiter.buckets)
		limiter.mu.Unlock()
		if n == 0 {
			break
		}
		select {
		case <-deadline:
			t.Fatal("background cleanup never reclaimed the idle bucket")
		case <-time.After(time.Millisecond):
		}
	}

	// A non-positive interval must not start a goroutine or panic.
	limiter.StartCleanup(context.Background(), 0)
}

func TestAllowNamedWithRetryAfterCooldown(t *testing.T) {
	limiter := New(map[string]ratelimit.Limit{
		"request_code": {Limit: 6, Window: time.Hour, Cooldown: time.Minute},
	})

	allowed, retryAfter, err := allowRetry(limiter,"request_code", "user")
	if err != nil {
		t.Fatal(err)
	}
	if !allowed || retryAfter != 0 {
		t.Fatalf("first request allowed=%v retry_after=%s, want allowed with no retry_after", allowed, retryAfter)
	}

	allowed, retryAfter, err = allowRetry(limiter,"request_code", "user")
	if err != nil {
		t.Fatal(err)
	}
	if allowed {
		t.Fatal("second request was allowed during cooldown")
	}
	if retryAfter < 59*time.Second || retryAfter > time.Minute {
		t.Fatalf("retry_after=%s, want about 60s", retryAfter)
	}
}

func TestAllowNamedWithRetryAfterWindowUsesLongestReset(t *testing.T) {
	limiter := New(map[string]ratelimit.Limit{
		"request_code": {Limit: 1, Window: time.Hour, Cooldown: time.Minute},
	})

	allowed, _, err := allowRetry(limiter,"request_code", "user")
	if err != nil {
		t.Fatal(err)
	}
	if !allowed {
		t.Fatal("first request denied")
	}

	allowed, retryAfter, err := allowRetry(limiter,"request_code", "user")
	if err != nil {
		t.Fatal(err)
	}
	if allowed {
		t.Fatal("second request was allowed")
	}
	if retryAfter < 59*time.Minute || retryAfter > time.Hour {
		t.Fatalf("retry_after=%s, want window reset around 1h", retryAfter)
	}
}

// allowRetry adapts AllowNamedResult to the (allowed, retryAfter, err) shape these
// cooldown/window tests assert on, after the dedicated AllowNamedWithRetryAfter
// wrapper was removed (#189). The retry-after value comes from AllowNamedResult.
func allowRetry(l *Limiter, bucket, key string) (bool, time.Duration, error) {
	r, err := l.AllowNamedResult(bucket, key)
	return r.Allowed, r.RetryAfter, err
}
