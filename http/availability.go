package authhttp

import (
	"math"
	"strings"
	"time"

	"github.com/open-rails/authkit/ratelimit"
)

const (
	ActionUpdateUsername           = "update_username"
	ActionRequestPasswordReset     = "request_password_reset"
	ActionRequestEmailVerification = "request_email_verification"
	ActionRequestPhoneVerification = "request_phone_verification"
)

type ActionAvailability struct {
	Action            string     `json:"action"`
	Allowed           bool       `json:"allowed"`
	Reason            string     `json:"reason,omitempty"`
	RetryAfterSeconds int64      `json:"retry_after_seconds,omitempty"`
	NextAllowedAt     *time.Time `json:"next_allowed_at,omitempty"`
	Limit             *int       `json:"limit,omitempty"`
	Remaining         *int       `json:"remaining,omitempty"`
	WindowSeconds     *int64     `json:"window_seconds,omitempty"`
	CooldownSeconds   *int64     `json:"cooldown_seconds,omitempty"`
}

func availabilityFromRateLimit(bucket string, result ratelimit.Result, now time.Time) ActionAvailability {
	out := ActionAvailability{
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

func cooldownAvailability(action string, retryAfterSeconds int64, cooldown time.Duration, now time.Time) ActionAvailability {
	if retryAfterSeconds < 0 {
		retryAfterSeconds = 0
	}
	next := now.Add(time.Duration(retryAfterSeconds) * time.Second).UTC()
	cooldownSeconds := int64(math.Ceil(cooldown.Seconds()))
	return ActionAvailability{
		Action:            action,
		Allowed:           retryAfterSeconds == 0,
		Reason:            ratelimit.ReasonCooldown,
		RetryAfterSeconds: retryAfterSeconds,
		NextAllowedAt:     &next,
		CooldownSeconds:   &cooldownSeconds,
	}
}

func actionForRateLimitBucket(bucket string) string {
	switch bucket {
	case RLPasswordResetRequest:
		return ActionRequestPasswordReset
	case RLEmailVerifyRequest, RLAuthRegisterResendEmail, RLUserEmailChangeRequest, RLUserEmailChangeResend:
		return ActionRequestEmailVerification
	case RLPhoneVerifyRequest, RLAuthRegisterResendPhone, RLUserPhoneChangeRequest, RLUserPhoneChangeResend:
		return ActionRequestPhoneVerification
	default:
		action := strings.TrimPrefix(strings.TrimSpace(bucket), "auth_")
		if action == "" {
			return "unknown"
		}
		return action
	}
}
