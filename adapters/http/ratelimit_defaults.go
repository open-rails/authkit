package authhttp

import (
	"time"

	memorylimiter "github.com/PaulFidika/authkit/ratelimit/memory"
	redislimiter "github.com/PaulFidika/authkit/ratelimit/redis"
)

// Limit configures a named rate limit bucket.
type Limit struct {
	Limit  int
	Window time.Duration
}

// DefaultRateLimits returns AuthKit's built-in per-endpoint rate limits.
//
// These limits are enforced per client IP (as determined by the Service's ClientIPFunc).
// Hosts can override by supplying their own limiter via WithRateLimiter(...).
func DefaultRateLimits() map[string]Limit {
	return map[string]Limit{
		"default": {Limit: 120, Window: time.Minute},

		// Registration + login + token exchange
		RLAuthToken:               {Limit: 30, Window: time.Minute},
		RLAuthRegister:            {Limit: 10, Window: time.Hour},
		RLAuthRegisterResendEmail: {Limit: 6, Window: 10 * time.Minute},
		RLAuthRegisterResendPhone: {Limit: 6, Window: 10 * time.Minute},
		RLPasswordLogin:           {Limit: 20, Window: time.Hour},

		// Logout + sessions
		RLAuthLogout:          {Limit: 60, Window: 10 * time.Minute},
		RLAuthSessionsCurrent: {Limit: 60, Window: 10 * time.Minute},
		RLAuthSessionsList:    {Limit: 120, Window: time.Minute},
		RLAuthSessionsRevoke:  {Limit: 60, Window: 10 * time.Minute},
		RLAuthSessionsRevokeAll: {
			Limit:  20,
			Window: time.Hour,
		},

		// Password reset + verification
		RLPasswordResetRequest: {Limit: 6, Window: 10 * time.Minute},
		RLPasswordResetConfirm: {Limit: 10, Window: 10 * time.Minute},
		RLEmailVerifyRequest:   {Limit: 6, Window: 10 * time.Minute},
		RLEmailVerifyConfirm:   {Limit: 10, Window: 10 * time.Minute},
		RLPhoneVerifyRequest:   {Limit: 3, Window: 10 * time.Minute},

		// User changes
		RLUserPasswordChange:     {Limit: 6, Window: time.Hour},
		RLUserMe:                 {Limit: 120, Window: time.Minute},
		RLUserUpdateUsername:     {Limit: 12, Window: time.Hour},
		RLUserUpdateEmail:        {Limit: 12, Window: time.Hour},
		RLUserEmailChangeRequest: {Limit: 6, Window: time.Hour},
		RLUserEmailChangeConfirm: {Limit: 10, Window: 10 * time.Minute},
		RLUserEmailChangeResend:  {Limit: 6, Window: 10 * time.Minute},
		RLUserPhoneChangeRequest: {Limit: 3, Window: 10 * time.Minute},
		RLUserPhoneChangeConfirm: {Limit: 10, Window: 10 * time.Minute},
		RLUserPhoneChangeResend:  {Limit: 3, Window: 10 * time.Minute},
		RLUserDelete:             {Limit: 6, Window: time.Hour},
		RLUserUnlinkProvider:     {Limit: 12, Window: time.Hour},

		// OIDC / OAuth browser flows
		RLOIDCStart:    {Limit: 30, Window: 10 * time.Minute},
		RLOIDCCallback: {Limit: 60, Window: 10 * time.Minute},

		// Solana SIWS
		RLSolanaChallenge: {Limit: 30, Window: 10 * time.Minute},
		RLSolanaLogin:     {Limit: 20, Window: 10 * time.Minute},
		RLSolanaLink:      {Limit: 12, Window: time.Hour},

		// Two-factor setup + verify
		RL2FAStartPhone:      {Limit: 3, Window: 10 * time.Minute},
		RL2FAEnable:          {Limit: 6, Window: time.Hour},
		RL2FADisable:         {Limit: 6, Window: time.Hour},
		RL2FARegenerateCodes: {Limit: 3, Window: time.Hour},
		RL2FAVerify:          {Limit: 10, Window: 10 * time.Minute},

		// Admin
		RLAdminRolesGrant:            {Limit: 30, Window: time.Hour},
		RLAdminRolesRevoke:           {Limit: 30, Window: time.Hour},
		RLAdminUserSessionsList:      {Limit: 600, Window: time.Hour},
		RLAdminUserSessionsRevokeAll: {Limit: 30, Window: time.Hour},
	}
}

func ToMemoryLimits(in map[string]Limit) map[string]memorylimiter.Limit {
	out := make(map[string]memorylimiter.Limit, len(in))
	for k, v := range in {
		out[k] = memorylimiter.Limit{Limit: v.Limit, Window: v.Window}
	}
	return out
}

func ToRedisLimits(in map[string]Limit) map[string]redislimiter.Limit {
	out := make(map[string]redislimiter.Limit, len(in))
	for k, v := range in {
		out[k] = redislimiter.Limit{Limit: v.Limit, Window: v.Window}
	}
	return out
}
