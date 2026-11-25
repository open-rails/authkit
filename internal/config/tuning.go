package config

import (
	"errors"
	"maps"
	"time"

	"github.com/open-rails/authkit/internal/ratelimit"
)

// Tuning is AuthKit's fixed limits and intervals. Every host runs with the
// defaults; only tests change them: AuthKit's own through Tune, a host's
// through authtest.LiftLimits.
type Tuning struct {
	// RateLimits overlays bucket limits onto the HTTP surface's defaults,
	// or with NoRateLimits onto none.
	RateLimits   map[string]RateLimit
	NoRateLimits bool
	// AccountsPerDevice, AccountsPerAddress and NewDevicesPerAccount cap
	// sign-ins over a rolling 24 hours (5, 20 and 10); negative is off.
	AccountsPerDevice, AccountsPerAddress, NewDevicesPerAccount int
	// SessionMaxPerUser caps a user's refresh sessions, evicting the oldest
	// (3); negative is unlimited.
	SessionMaxPerUser int
	// PrivateNetworkJWKS admits http and private or loopback JWKS and
	// metadata URLs. Always on for a loopback issuer.
	PrivateNetworkJWKS bool
	// SenderHealthInterval is how often Start re-runs the senders'
	// CheckHealth (5 minutes); SenderHealthRecheck how soon after a failed
	// check or send (30 seconds, never longer than the interval).
	SenderHealthInterval, SenderHealthRecheck time.Duration
	// VerificationSendTimeout bounds one in-line email or SMS send (15s).
	VerificationSendTimeout time.Duration
	// EventRetention keeps committed account and group events (90 days).
	EventRetention time.Duration
	// SessionEventRetention keeps session-event history, personal data
	// (365 days); negative keeps it forever.
	SessionEventRetention time.Duration
}

// Defaults of Tuning.
const (
	DefaultAccountsPerDevice    = 5
	DefaultAccountsPerAddress   = 20
	DefaultNewDevicesPerAccount = 10
	DefaultSessionMaxPerUser    = 3
)

// Tune changes c's tuning: tests only.
func Tune(c *Config, fn func(*Tuning)) {
	t := c.tuning
	t.RateLimits = maps.Clone(t.RateLimits)
	if t.RateLimits == nil {
		t.RateLimits = map[string]RateLimit{}
	}
	fn(&t)
	c.tuning = t
}

// LiftLimits lifts every limit a test would trip: the rate limits, the
// sign-in limits and the session cap, and admits private-network JWKS.
func LiftLimits(c *Config) {
	Tune(c, func(t *Tuning) {
		t.NoRateLimits = true
		t.AccountsPerDevice, t.AccountsPerAddress, t.NewDevicesPerAccount = -1, -1, -1
		t.SessionMaxPerUser = -1
		t.PrivateNetworkJWKS = true
	})
}

// Tuned is a normalized c's tuning.
func Tuned(c Config) Tuning { return c.tuning }

func normalizeTuning(c *Config) error {
	t := c.tuning
	for _, f := range []struct {
		value *int
		def   int
	}{
		{&t.AccountsPerDevice, DefaultAccountsPerDevice},
		{&t.AccountsPerAddress, DefaultAccountsPerAddress},
		{&t.NewDevicesPerAccount, DefaultNewDevicesPerAccount},
		{&t.SessionMaxPerUser, DefaultSessionMaxPerUser},
	} {
		if *f.value == 0 {
			*f.value = f.def
		}
	}
	t.PrivateNetworkJWKS = t.PrivateNetworkJWKS || LoopbackURL(c.Issuer)
	if t.SenderHealthInterval <= 0 {
		t.SenderHealthInterval = 5 * time.Minute
	}
	if t.SenderHealthRecheck <= 0 {
		t.SenderHealthRecheck = 30 * time.Second
	}
	t.SenderHealthRecheck = min(t.SenderHealthRecheck, t.SenderHealthInterval)
	if t.VerificationSendTimeout <= 0 {
		t.VerificationSendTimeout = 15 * time.Second
	}
	if t.EventRetention == 0 {
		t.EventRetention = 90 * 24 * time.Hour
	}
	if t.EventRetention < time.Second {
		return errors.New("authkit: EventRetention must be at least one second")
	}
	if t.SessionEventRetention == 0 {
		t.SessionEventRetention = 365 * 24 * time.Hour
	}
	if err := ratelimit.ValidateLimits(t.RateLimits); err != nil {
		return err
	}
	c.tuning = t
	return nil
}
