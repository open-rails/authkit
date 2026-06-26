package authhttp

import (
	"net"
	"net/http"
	"time"

	"github.com/open-rails/authkit/ratelimit"
)

// RateLimiter is a minimal interface used by adapters.
type RateLimiter interface {
	AllowNamed(bucket string, key string) (bool, error)
}

type RateLimitResult struct {
	Allowed      bool
	RetryAfter   time.Duration
	Availability *ActionAvailability
}

type RateLimiterWithResult interface {
	AllowNamedResult(bucket string, key string) (ratelimit.Result, error)
}

func clientIP(r *http.Request) string {
	if r == nil {
		return ""
	}
	// Conservative: prefer RemoteAddr (works for local/dev and typical reverse proxy setups when trusted layer overwrites).
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err == nil && host != "" {
		return host
	}
	return r.RemoteAddr
}
