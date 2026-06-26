package authhttp

import (
	"testing"

	memorylimiter "github.com/open-rails/authkit/ratelimit/memory"
	redislimiter "github.com/open-rails/authkit/ratelimit/redis"
	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/require"
)

// TestRateLimiter_AutoWiring pins #143: AuthKit owns the rate-limit policy and
// auto-creates the limiter — Redis-backed when authhttp.WithRedis is supplied,
// in-memory otherwise — without the host wiring a limiter. The WithRateLimiter /
// WithoutRateLimiter seams remain for advanced/test use only.
func TestRateLimiter_AutoWiring(t *testing.T) {
	cfg := newServerTestConfig() // dev env: no Redis requirement

	t.Run("no Redis -> in-memory limiter", func(t *testing.T) {
		srv, err := NewServer(newServerClient(t, cfg, newNoDBPool(t)))
		require.NoError(t, err)
		_, ok := srv.rl.(*memorylimiter.Limiter)
		require.Truef(t, ok, "want in-memory limiter, got %T", srv.rl)
	})

	t.Run("WithRedis -> Redis-backed limiter", func(t *testing.T) {
		// Client is not dialed during construction, so no live Redis is needed.
		rdb := redis.NewClient(&redis.Options{Addr: "127.0.0.1:0"})
		t.Cleanup(func() { _ = rdb.Close() })
		srv, err := NewServer(newServerClient(t, cfg, newNoDBPool(t)), WithRedis(rdb))
		require.NoError(t, err)
		_, ok := srv.rl.(*redislimiter.Limiter)
		require.Truef(t, ok, "want Redis-backed limiter, got %T", srv.rl)
	})

	t.Run("WithoutRateLimiter -> disabled", func(t *testing.T) {
		srv, err := NewServer(newServerClient(t, cfg, newNoDBPool(t)), WithoutRateLimiter())
		require.NoError(t, err)
		require.Nil(t, srv.rl, "WithoutRateLimiter should disable rate limiting")
	})
}
