package authhttp

import (
	"errors"
	"net/http"
	"testing"

	"github.com/open-rails/authkit/internal/testdb"
	redislimiter "github.com/open-rails/authkit/ratelimit/redis"
	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/require"
)

// erroringLimiter simulates a rate-limiter backend outage (e.g. Redis down): every
// check returns an error. It implements only the base RateLimiter, so allowResult
// falls through to the AllowNamed error path.
type erroringLimiter struct{}

func (erroringLimiter) AllowNamed(bucket, key string) (bool, error) {
	return false, errors.New("rate limiter backend unavailable")
}

// TestRateLimiter_FailsClosedOnBackendError is the AK2-AUTH-05 regression: when the
// limiter errors, the credential-VERIFICATION buckets (2FA verify, password login,
// code confirmations) must DENY (fail closed) so losing the limiter cannot silently
// remove the only online brute-force defense; all other buckets keep failing OPEN so
// an outage degrades availability rather than the whole auth surface.
func TestRateLimiter_FailsClosedOnBackendError(t *testing.T) {
	s := &Service{rl: erroringLimiter{}, clientIP: func(*http.Request) string { return "203.0.113.7" }}
	req, _ := http.NewRequest(http.MethodPost, "/x", nil)

	for b := range failClosedBuckets {
		// IP-keyed path.
		if s.allowResult(req, b).Allowed {
			t.Errorf("bucket %q: limiter error must FAIL CLOSED (deny), got Allowed=true", b)
		}
		// per-identifier path (used by 2FA-verify / password-login).
		if s.allowResultForKey(b, b+":id:victim").Allowed {
			t.Errorf("bucket %q (per-identifier): limiter error must FAIL CLOSED, got Allowed=true", b)
		}
	}

	// Non-sensitive buckets keep failing OPEN.
	for _, b := range []string{RLUserMe, RLAuthSessionsList, RLAuthLogout, "default"} {
		if !s.allowResult(req, b).Allowed {
			t.Errorf("bucket %q: limiter error must fail OPEN (allow), got Allowed=false", b)
		}
		if !s.allowResultForKey(b, b+":id:x").Allowed {
			t.Errorf("bucket %q (per-identifier): limiter error must fail OPEN, got Allowed=false", b)
		}
	}
}

// TestRateLimiter_FailsClosedOnRedisOutage reaches the same classification
// through the real Redis limiter with a closed client, so the deny-on-error
// branch is exercised by a genuine backend error rather than a fake.
func TestRateLimiter_FailsClosedOnRedisOutage(t *testing.T) {
	live := testdb.ScratchRedis(t)
	o := *live.Options()
	closed := redis.NewClient(&o)
	require.NoError(t, closed.Close())
	s := &Service{rl: redislimiter.New(closed, DefaultRateLimits(), "authkit:profiles:ratelimit:"), clientIP: func(*http.Request) string { return "203.0.113.7" }}
	req, _ := http.NewRequest(http.MethodPost, "/x", nil)

	for b := range failClosedBuckets {
		require.Falsef(t, s.allowResult(req, b).Allowed, "bucket %q: Redis outage must fail closed", b)
		require.Falsef(t, s.allowResultForKey(b, b+":id:victim").Allowed, "bucket %q (per-identifier): Redis outage must fail closed", b)
	}
	for _, b := range []string{RLUserMe, RLAuthSessionsList, RLAuthLogout, "default"} {
		require.Truef(t, s.allowResult(req, b).Allowed, "bucket %q: Redis outage must fail open", b)
		require.Truef(t, s.allowResultForKey(b, b+":id:x").Allowed, "bucket %q (per-identifier): Redis outage must fail open", b)
	}
}

// TestRateLimiter_NilLimiterFailsOpen confirms a deliberately-absent limiter
// (WithoutRateLimiter / s.rl == nil) still ALLOWS even for sensitive buckets —
// opting out of rate limiting is a configuration choice, not an outage, and must
// not deny every login.
func TestRateLimiter_NilLimiterFailsOpen(t *testing.T) {
	s := &Service{rl: nil, clientIP: func(*http.Request) string { return "203.0.113.7" }}
	req, _ := http.NewRequest(http.MethodPost, "/x", nil)
	if !s.allowResult(req, RL2FAVerify).Allowed {
		t.Fatal("nil limiter (deliberate opt-out) must fail open, got deny")
	}
	if !s.allowResultForKey(RL2FAVerify, "2fa:id:x").Allowed {
		t.Fatal("nil limiter (per-identifier) must fail open, got deny")
	}
}

// TestLimiterErrorResult pins the bucket-classification helper directly.
func TestLimiterErrorResult(t *testing.T) {
	for b := range failClosedBuckets {
		if limiterErrorResult(b).Allowed {
			t.Errorf("%q must fail closed on limiter error", b)
		}
	}
	if !limiterErrorResult(RLUserMe).Allowed {
		t.Error("RLUserMe must fail open on limiter error")
	}
}
