package authhttp

import (
	"errors"
	"net/http"
	"testing"
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
		if s.allowResultForKey(b, "auth:"+b+":id:victim").Allowed {
			t.Errorf("bucket %q (per-identifier): limiter error must FAIL CLOSED, got Allowed=true", b)
		}
	}

	// Non-sensitive buckets keep failing OPEN.
	for _, b := range []string{RLUserMe, RLAuthSessionsList, RLAuthLogout, "default"} {
		if !s.allowResult(req, b).Allowed {
			t.Errorf("bucket %q: limiter error must fail OPEN (allow), got Allowed=false", b)
		}
		if !s.allowResultForKey(b, "auth:"+b+":id:x").Allowed {
			t.Errorf("bucket %q (per-identifier): limiter error must fail OPEN, got Allowed=false", b)
		}
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
	if !s.allowResultForKey(RL2FAVerify, "auth:2fa:id:x").Allowed {
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
