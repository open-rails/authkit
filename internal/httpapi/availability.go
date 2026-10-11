package httpapi

import (
	"math"
	"strings"
	"time"

	"github.com/open-rails/authkit/internal/authflow"
	"github.com/open-rails/authkit/internal/errmodel"
	"github.com/open-rails/authkit/internal/ratelimit"
)

func availabilityFromRateLimit(bucket string, result ratelimit.Result, now time.Time) authflow.ActionAvailability {
	out := authflow.ActionAvailability{
		Action:  actionForRateLimitBucket(bucket),
		Allowed: result.Allowed,
		Reason:  strings.TrimSpace(result.Reason),
	}
	if result.RetryAfter > 0 {
		seconds := int64(math.Ceil(result.RetryAfter.Seconds()))
		if seconds < 1 {
			seconds = 1
		}
		next := now.Add(time.Duration(seconds) * time.Second).UTC()
		out.RetryAfterSeconds = seconds
		out.NextAllowedAt = &next
	}
	if result.Limit > 0 {
		limit := result.Limit
		out.Limit = &limit
	}
	if result.Limit > 0 || result.Remaining > 0 {
		remaining := result.Remaining
		out.Remaining = &remaining
	}
	if result.Window > 0 {
		seconds := int64(math.Ceil(result.Window.Seconds()))
		out.WindowSeconds = &seconds
	}
	if result.Cooldown > 0 {
		seconds := int64(math.Ceil(result.Cooldown.Seconds()))
		out.CooldownSeconds = &seconds
	}
	return out
}

func actionForRateLimitBucket(bucket string) string {
	switch bucket {
	case RLPasswordResetRequest:
		return authflow.ActionRequestPasswordReset
	case RLVerifyRequest, RLMeContactChange:
		return authflow.ActionRequestVerification
	default:
		return bucket
	}
}

// RateLimitError is rate_limited for a refusal of bucket, for a limit the
// engine applies (SMSConfig's sends).
func RateLimitError(bucket string, result ratelimit.Result) error {
	return errmodel.E(errmodel.CodeRateLimited, errmodel.WithDetails(availabilityFromRateLimit(bucket, result, time.Now())))
}
