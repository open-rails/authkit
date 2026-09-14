package ratelimit_test

import (
	"testing"
	"time"

	"github.com/open-rails/authkit/authhttp"
	"github.com/open-rails/authkit/internal/testdb"
	"github.com/open-rails/authkit/ratelimit"
	memorylimiter "github.com/open-rails/authkit/ratelimit/memory"
	redislimiter "github.com/open-rails/authkit/ratelimit/redis"
	"github.com/stretchr/testify/require"
)

func TestBackendsRejectTheSameInvalidLimits(t *testing.T) {
	rdb := testdb.ScratchRedis(t)
	for name, limit := range map[string]ratelimit.Limit{
		"zero":                 {Limit: 0, Window: time.Minute},
		"negative":             {Limit: -1, Window: time.Minute},
		"zero_window":          {Limit: 1},
		"negative_window":      {Limit: 1, Window: -time.Second},
		"sub_ms_window":        {Limit: 1, Window: time.Microsecond},
		"fractional_ms_window": {Limit: 1, Window: time.Millisecond + time.Nanosecond},
		"negative_cooldown":    {Limit: 1, Window: time.Minute, Cooldown: -time.Second},
		"sub_ms_cooldown":      {Limit: 1, Window: time.Minute, Cooldown: time.Microsecond},
		"long_cooldown":        {Limit: 1, Window: time.Second, Cooldown: 2 * time.Second},
	} {
		t.Run(name, func(t *testing.T) {
			limits := map[string]ratelimit.Limit{"test": limit}
			err := (authhttp.Config{DirectPeerIP: true, RateLimits: limits}).Validate()
			require.Error(t, err)
			mem, memErr := memorylimiter.New(limits)
			red, redErr := redislimiter.New(rdb, limits, "invalid:")
			require.Nil(t, mem)
			require.Nil(t, red)
			require.EqualError(t, memErr, err.Error())
			require.EqualError(t, redErr, err.Error())
		})
	}
	_, err := memorylimiter.New(nil, memorylimiter.WithMaxBuckets(0))
	require.Error(t, err)
	_, err = memorylimiter.New(nil, memorylimiter.WithMaxBuckets(-1))
	require.Error(t, err)
	_, err = memorylimiter.New(nil, memorylimiter.WithClock(nil))
	require.Error(t, err)
	_, err = redislimiter.New(nil, nil, "nil:")
	require.Error(t, err)
	keys, err := rdb.Keys(t.Context(), "invalid:*").Result()
	require.NoError(t, err)
	require.Empty(t, keys, "invalid configuration never touches backend storage")
}

func TestBackendPolicyParityAndSnapshot(t *testing.T) {
	rdb := testdb.ScratchRedis(t)
	for name, policy := range map[string]struct {
		limit    ratelimit.Limit
		accepted int
		reason   string
	}{
		"threshold":                 {ratelimit.Limit{Limit: 3, Window: time.Minute}, 3, ratelimit.ReasonLimitExceeded},
		"cooldown":                  {ratelimit.Limit{Limit: 6, Window: time.Minute, Cooldown: 10 * time.Second}, 1, ratelimit.ReasonCooldown},
		"window_dominates_cooldown": {ratelimit.Limit{Limit: 1, Window: time.Minute, Cooldown: 10 * time.Second}, 1, ratelimit.ReasonLimitExceeded},
	} {
		limit := policy.limit
		t.Run(name, func(t *testing.T) {
			limits := map[string]ratelimit.Limit{"test": limit}
			mem, err := memorylimiter.New(limits)
			require.NoError(t, err)
			red, err := redislimiter.New(rdb, limits, name+":")
			require.NoError(t, err)
			limits["test"] = ratelimit.Limit{Limit: 0} // Caller mutation cannot weaken either backend.
			for i := range 5 {
				a, err := mem.AllowNamedResult("test", "user")
				require.NoError(t, err)
				b, err := red.AllowNamedResult("test", "user")
				require.NoError(t, err)
				require.Equal(t, i < policy.accepted, a.Allowed)
				require.Equal(t, a.Allowed, b.Allowed)
				require.Equal(t, limit.Limit-min(i+1, policy.accepted), a.Remaining)
				require.Equal(t, a.Remaining, b.Remaining)
				require.Equal(t, a.Reason, b.Reason)
				require.Equal(t, a.Limit, b.Limit)
				require.Equal(t, a.Window, b.Window)
				require.Equal(t, a.Cooldown, b.Cooldown)
				if !a.Allowed {
					require.Equal(t, policy.reason, a.Reason)
					if name == "window_dominates_cooldown" {
						require.Greater(t, a.RetryAfter, limit.Cooldown)
						require.Greater(t, b.RetryAfter, limit.Cooldown)
					}
					require.Positive(t, a.RetryAfter)
					require.Positive(t, b.RetryAfter)
					require.LessOrEqual(t, a.RetryAfter, limit.Window)
					require.LessOrEqual(t, b.RetryAfter, limit.Window)
				}
			}
			a, err := mem.AllowNamedResult("test", "other-user")
			require.NoError(t, err)
			b, err := red.AllowNamedResult("test", "other-user")
			require.NoError(t, err)
			require.True(t, a.Allowed)
			require.Equal(t, a, b)
			a, err = mem.AllowNamedResult("other-bucket", "user")
			require.NoError(t, err)
			b, err = red.AllowNamedResult("other-bucket", "user")
			require.NoError(t, err)
			require.True(t, a.Allowed)
			require.Equal(t, 100, a.Limit)
			require.Equal(t, a, b)
			ttl, err := rdb.PTTL(t.Context(), name+":user:test").Result()
			require.NoError(t, err)
			require.Positive(t, ttl)
			require.LessOrEqual(t, ttl, limit.Window)
		})
	}
	require.NoError(t, ratelimit.ValidateLimits(authhttp.DefaultRateLimits()))
	mem, err := memorylimiter.New(nil)
	require.NoError(t, err)
	red, err := redislimiter.New(rdb, nil, "fallback:")
	require.NoError(t, err)
	a, err := mem.AllowNamedResult("unknown", "user")
	require.NoError(t, err)
	b, err := red.AllowNamedResult("unknown", "user")
	require.NoError(t, err)
	require.Equal(t, a, b)
}
