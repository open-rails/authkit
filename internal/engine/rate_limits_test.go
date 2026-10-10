package engine

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/open-rails/authkit/internal/ratelimit"
)

// The maintenance sweep deletes dead budgets in batches and keeps live ones.
func TestRateLimitSweepPurgesOnlyDeadBudgets(t *testing.T) {
	core := ephemeralEngine(t)
	ctx := t.Context()
	_, err := core.pg.Exec(ctx, `INSERT INTO rate_limits (key, hits, expires_at)
SELECT 'dead:' || i, '{1}', now() - interval '1 second' FROM generate_series(1, $1::int) i`, 2*ephemeralSweepBatch+5)
	require.NoError(t, err)
	limiter, err := core.RateLimiter(map[string]ratelimit.Limit{"login": {Limit: 1, Window: time.Hour}})
	require.NoError(t, err)
	r, err := limiter.Allow(ctx, "login", "ip:203.0.113.1")
	require.NoError(t, err)
	require.True(t, r.Allowed)

	require.NoError(t, core.cleanupExpiredAuthState(ctx))
	var rows int
	require.NoError(t, core.pg.QueryRow(ctx, `SELECT count(*) FROM rate_limits`).Scan(&rows))
	require.Equal(t, 1, rows)
	r, err = limiter.Allow(ctx, "login", "ip:203.0.113.1")
	require.NoError(t, err)
	require.False(t, r.Allowed, "the live budget survived the sweep")
}
