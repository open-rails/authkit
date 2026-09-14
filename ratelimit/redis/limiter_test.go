package redislimiter

import (
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/open-rails/authkit/internal/testdb"
	"github.com/open-rails/authkit/ratelimit"
	"github.com/redis/go-redis/v9"
)

func TestAllowNamedResultWindowResets(t *testing.T) {
	l := newLimiter(t, testdb.ScratchRedis(t), map[string]ratelimit.Limit{
		"probe": {Limit: 2, Window: 200 * time.Millisecond},
	}, "t:")
	for i := 0; i < 2; i++ {
		if r, err := l.AllowNamedResult("probe", "k"); err != nil || !r.Allowed {
			t.Fatalf("request %d: %+v err=%v", i, r, err)
		}
	}
	r, err := l.AllowNamedResult("probe", "k")
	if err != nil || r.Allowed || r.RetryAfter > 200*time.Millisecond {
		t.Fatalf("3rd request: %+v err=%v, want denied with RetryAfter <= window", r, err)
	}
	time.Sleep(250 * time.Millisecond)
	if r, err := l.AllowNamedResult("probe", "k"); err != nil || !r.Allowed {
		t.Fatalf("after window: %+v err=%v, want allowed again", r, err)
	}
}

// The Lua script decides and records in one atomic step (#217): racing callers
// never over-admit past the limit.
func TestAllowNamedAdmitsExactlyLimitUnderConcurrency(t *testing.T) {
	const limit, racers = 10, 64
	l := newLimiter(t, testdb.ScratchRedis(t), map[string]ratelimit.Limit{
		"race": {Limit: limit, Window: time.Minute},
	}, "t:")

	var allowed, errs int64
	var wg sync.WaitGroup
	start := make(chan struct{})
	for i := 0; i < racers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			ok, err := l.AllowNamed("race", "k")
			if err != nil {
				atomic.AddInt64(&errs, 1)
			}
			if ok {
				atomic.AddInt64(&allowed, 1)
			}
		}()
	}
	close(start)
	wg.Wait()
	if errs != 0 || allowed != limit {
		t.Fatalf("allowed=%d errs=%d, want exactly %d admitted and no errors", allowed, errs, limit)
	}
}

// A backend failure surfaces as err != nil so authhttp can fail closed on the
// credential-verification buckets; it must never masquerade as "allowed".
func TestAllowNamedResultBackendErrorSurfaces(t *testing.T) {
	live := testdb.ScratchRedis(t)
	o := *live.Options()
	closed := redis.NewClient(&o)
	if err := closed.Close(); err != nil {
		t.Fatal(err)
	}
	l := newLimiter(t, closed, map[string]ratelimit.Limit{"login": {Limit: 3, Window: time.Minute}}, "t:")

	if r, err := l.AllowNamedResult("login", "ip"); err == nil || r.Allowed {
		t.Fatalf("closed client: got (%+v, %v), want an error and Allowed=false", r, err)
	}
	if ok, err := l.AllowNamed("login", "ip"); err == nil || ok {
		t.Fatalf("closed client AllowNamed: got (%v, %v), want (false, error)", ok, err)
	}
}

func newLimiter(t testing.TB, rdb *redis.Client, limits map[string]ratelimit.Limit, prefix string) *Limiter {
	t.Helper()
	l, err := New(rdb, limits, prefix)
	if err != nil {
		t.Fatal(err)
	}
	return l
}
