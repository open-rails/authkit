package authhttp

import (
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
