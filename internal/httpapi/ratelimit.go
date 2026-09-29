package httpapi

import (
	"time"

	"github.com/open-rails/authkit/internal/authflow"
	"github.com/open-rails/authkit/internal/ratelimit"
)

// RateLimiter is a minimal interface used by adapters.
type RateLimiter interface {
	AllowNamed(bucket string, key string) (bool, error)
}

type RateLimitResult struct {
	Allowed      bool
	RetryAfter   time.Duration
	Availability *authflow.ActionAvailability
}

type RateLimiterWithResult interface {
	AllowNamedResult(bucket string, key string) (ratelimit.Result, error)
}
