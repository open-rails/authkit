package pglimiter_test

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/open-rails/authkit/internal/db"
	"github.com/open-rails/authkit/internal/ratelimit"
	pglimiter "github.com/open-rails/authkit/internal/ratelimit/postgres"
	"github.com/open-rails/authkit/internal/testdb"
	"github.com/stretchr/testify/require"
)

// newLimiter is a limiter on its own pool over a scratch AuthKit schema.
func newLimiter(t *testing.T, pg *testdb.Postgres, limits map[string]ratelimit.Limit) *pglimiter.Limiter {
	t.Helper()
	cfg, err := pgxpool.ParseConfig(pg.URL)
	require.NoError(t, err)
	cfg.ConnConfig.RuntimeParams["search_path"] = "profiles, public"
	pool, err := pgxpool.NewWithConfig(context.Background(), cfg)
	require.NoError(t, err)
	t.Cleanup(pool.Close)
	l, err := pglimiter.New(db.New(pool), limits)
	require.NoError(t, err)
	return l
}

func allow(t *testing.T, l *pglimiter.Limiter, bucket, key string) ratelimit.Result {
	t.Helper()
	r, err := l.Allow(t.Context(), bucket, key)
	require.NoError(t, err)
	return r
}

// TestSlidingWindow: Limit requests per Window, each hit lapsing on its own;
// a Cooldown after each admitted request; a refusal records nothing and says
// when to retry. Limiters on separate pools spend one budget, and concurrent
// requests never admit past the limit.
func TestSlidingWindow(t *testing.T) {
	pg := testdb.ScratchPostgres(t)
	limits := map[string]ratelimit.Limit{
		"burst": {Limit: 3, Window: 2 * time.Second},
		"cool":  {Limit: 5, Window: time.Hour, Cooldown: time.Second},
		"race":  {Limit: 10, Window: time.Hour},
	}
	one, two := newLimiter(t, pg, limits), newLimiter(t, pg, limits)

	t.Run("limit per window, shared by every limiter", func(t *testing.T) {
		for i, l := range []*pglimiter.Limiter{one, two, one} {
			r := allow(t, l, "burst", "k")
			require.True(t, r.Allowed, "request %d", i+1)
			require.Equal(t, 2-i, r.Remaining)
			require.Equal(t, 3, r.Limit)
		}
		r := allow(t, two, "burst", "k")
		require.False(t, r.Allowed)
		require.Equal(t, ratelimit.ReasonLimitExceeded, r.Reason)
		require.Zero(t, r.Remaining)
		require.Positive(t, r.RetryAfter)
		require.LessOrEqual(t, r.RetryAfter, 2*time.Second)
		require.True(t, allow(t, one, "burst", "other").Allowed, "another key has its own budget")

		time.Sleep(r.RetryAfter + 50*time.Millisecond)
		r = allow(t, one, "burst", "k")
		require.True(t, r.Allowed, "the oldest hit lapsed")
	})

	t.Run("cooldown after each admitted request", func(t *testing.T) {
		require.True(t, allow(t, one, "cool", "k").Allowed)
		r := allow(t, two, "cool", "k")
		require.False(t, r.Allowed)
		require.Equal(t, ratelimit.ReasonCooldown, r.Reason)
		require.Equal(t, 4, r.Remaining, "the refusal recorded nothing")
		require.Positive(t, r.RetryAfter)
		require.LessOrEqual(t, r.RetryAfter, time.Second)

		time.Sleep(r.RetryAfter + 50*time.Millisecond)
		r = allow(t, two, "cool", "k")
		require.True(t, r.Allowed)
		require.Equal(t, 3, r.Remaining)
	})

	t.Run("concurrent requests admit exactly the limit", func(t *testing.T) {
		var admitted, failed atomic.Int64
		var wg sync.WaitGroup
		for i := range 40 {
			wg.Go(func() {
				r, err := []*pglimiter.Limiter{one, two}[i%2].Allow(t.Context(), "race", "k")
				switch {
				case err != nil:
					failed.Add(1)
				case r.Allowed:
					admitted.Add(1)
				}
			})
		}
		wg.Wait()
		require.Zero(t, failed.Load())
		require.EqualValues(t, 10, admitted.Load())
	})
}
