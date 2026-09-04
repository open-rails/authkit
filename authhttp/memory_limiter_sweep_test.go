package authhttp

import (
	"fmt"
	"testing"
	"time"

	memorylimiter "github.com/open-rails/authkit/internal/ratelimit/memory"
	"github.com/open-rails/authkit/ratelimit"
	"github.com/stretchr/testify/require"
)

// #305: the in-memory limiter NewServer auto-creates is swept in the
// background, so buckets for keys that never return are reclaimed after their
// window; Close stops the sweep.
func TestNewServer_MemoryLimiterSweepsIdleBuckets(t *testing.T) {
	srv, err := NewServer(newServerClient(t, newServerTestConfig(), newServerTestPool(t)),
		WithRateLimitOverrides(map[string]ratelimit.Limit{"login": {Limit: 5, Window: 20 * time.Millisecond}}),
		withMemoryLimiterSweep(10*time.Millisecond))
	require.NoError(t, err)
	ml, ok := srv.rl.(*memorylimiter.Limiter)
	require.True(t, ok, "no Redis => memory limiter")

	for i := 0; i < 20; i++ {
		allowed, err := ml.AllowNamed("login", fmt.Sprintf("10.0.0.%d", i))
		require.NoError(t, err)
		require.True(t, allowed)
	}
	require.Equal(t, 20, ml.Len())
	require.Eventually(t, func() bool { return ml.Len() == 0 }, 2*time.Second, 5*time.Millisecond,
		"idle buckets must be reclaimed without further traffic")

	srv.Close()
	srv.Close()
	require.Nil(t, srv.closers)
}
