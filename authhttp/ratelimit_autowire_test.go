package authhttp

import (
	"testing"

	memorylimiter "github.com/open-rails/authkit/internal/ratelimit/memory"
	redislimiter "github.com/open-rails/authkit/internal/ratelimit/redis"
	"github.com/open-rails/authkit/internal/testdb"
	"github.com/stretchr/testify/require"
)

// TestRateLimiter_AutoWiring pins #143: AuthKit owns the rate-limit policy and
// auto-creates the limiter — Redis-backed when authhttp.WithRedis is supplied,
// in-memory otherwise — without the host wiring a limiter. The WithRateLimiter /
// WithoutRateLimiter seams remain for advanced/test use only.
func TestRateLimiter_AutoWiring(t *testing.T) {
	cfg := newServerTestConfig() // dev env: no Redis requirement

	t.Run("no Redis -> in-memory limiter", func(t *testing.T) {
		srv, err := NewServer(newServerClient(t, cfg, newTestPool(t)))
		require.NoError(t, err)
		_, ok := srv.rl.(*memorylimiter.Limiter)
		require.Truef(t, ok, "want in-memory limiter, got %T", srv.rl)
	})

	t.Run("WithRedis -> Redis-backed limiter", func(t *testing.T) {
		rdb := testdb.ScratchRedis(t)
		srv, err := NewServer(newServerClient(t, cfg, newTestPool(t)), WithRedis(rdb))
		require.NoError(t, err)
		_, ok := srv.rl.(*redislimiter.Limiter)
		require.Truef(t, ok, "want Redis-backed limiter, got %T", srv.rl)
		allowed, err := srv.rl.AllowNamed(RLPasswordLogin, "probe")
		require.NoError(t, err, "limiter must talk to the live Redis")
		require.True(t, allowed)
		require.EqualValues(t, 1, rdb.Exists(t.Context(), "authkit:profiles:ratelimit:probe:"+RLPasswordLogin).Val(), "limiter must record its bucket under the deployment namespace (#307)")
	})

	t.Run("WithoutRateLimiter -> disabled", func(t *testing.T) {
		srv, err := NewServer(newServerClient(t, cfg, newTestPool(t)), WithoutRateLimiter())
		require.NoError(t, err)
		require.Nil(t, srv.rl, "WithoutRateLimiter should disable rate limiting")
	})
}
