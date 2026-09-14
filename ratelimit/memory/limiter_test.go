package memorylimiter

import (
	"context"
	"testing"
	"time"

	"github.com/open-rails/authkit/internal/testclock"
	"github.com/open-rails/authkit/ratelimit"
)

func TestCleanupEvictsIdleBuckets(t *testing.T) {
	clk := testclock.New()
	limiter := newLimiter(t, map[string]ratelimit.Limit{
		"probe": {Limit: 5, Window: 20 * time.Millisecond},
	}, WithClock(clk.Now))

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
	clk.Advance(30 * time.Millisecond)
	if got := limiter.Cleanup(); got != 0 {
		t.Fatalf("Cleanup did not reclaim idle buckets: retained %d, want 0", got)
	}
}

func TestStartCleanupStopsOnContextCancel(t *testing.T) {
	limiter := newLimiter(t, map[string]ratelimit.Limit{
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

func newLimiter(t testing.TB, limits map[string]ratelimit.Limit, opts ...Option) *Limiter {
	t.Helper()
	l, err := New(limits, opts...)
	if err != nil {
		t.Fatal(err)
	}
	return l
}

func TestWindowBoundaryPrunesExpiredRequest(t *testing.T) {
	now := time.Unix(100, 0)
	l := newLimiter(t, map[string]ratelimit.Limit{"test": {Limit: 1, Window: time.Second}}, WithClock(func() time.Time { return now }))
	if ok, err := l.AllowNamed("test", "user"); err != nil || !ok {
		t.Fatalf("first request: allowed=%v err=%v", ok, err)
	}
	now = now.Add(time.Second)
	result, err := l.AllowNamedResult("test", "user")
	if err != nil || !result.Allowed || result.Remaining != 0 {
		t.Fatalf("boundary request: %+v err=%v", result, err)
	}
	if n := len(l.buckets["user:test"].timestamps); n != 1 {
		t.Fatalf("expired request retained at exact window boundary: %d entries", n)
	}
}
