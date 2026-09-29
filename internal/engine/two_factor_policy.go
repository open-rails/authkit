package engine

import (
	"strings"

	"github.com/open-rails/authkit/iam"
)

// Two-factor policy gating (#148). Mode/Methods from TwoFactorConfig decide which
// second factors can be enrolled, challenged, and verified. Disabled turns the
// whole flow off; otherwise only configured methods whose delivery dependency is
// present are usable (fail closed when a dependency — SMS sender, email sender, or
// TOTP key — is missing). These guard the core operations, so EVERY caller (HTTP
// handlers and direct embedders) is gated at one chokepoint.

// TwoFactorEnabled reports whether any 2FA flow is usable (Mode != Disabled).
func (s *Engine) TwoFactorEnabled() bool {
	return s.cfg.TwoFactor.Mode != iam.TwoFactorDisabled
}

func (s *Engine) twoFactorMethodConfigured(m iam.TwoFactorMethod) bool {
	if !s.TwoFactorEnabled() {
		return false
	}
	methods := s.cfg.TwoFactor.Methods
	if len(methods) == 0 {
		return true // empty Methods means all three are offered.
	}
	for _, x := range methods {
		if x == m {
			return true
		}
	}
	return false
}

// TwoFactorMethodAvailable reports whether a second-factor method can be
// enrolled/used right now: enabled by policy AND its delivery dependency present.
func (s *Engine) TwoFactorMethodAvailable(method string) bool {
	m := iam.TwoFactorMethod(strings.ToLower(strings.TrimSpace(method)))
	if !s.twoFactorMethodConfigured(m) {
		return false
	}
	switch m {
	case iam.TwoFactorSMS:
		return s.SMSAvailable()
	case iam.TwoFactorEmail:
		return s.email != nil
	case iam.TwoFactorTOTP:
		return len(s.cfg.TwoFactor.TOTPSecretKey) > 0
	default:
		return false
	}
}

// TwoFactorAllowedMethods is the set of currently-usable methods, in stable order.
// Empty when 2FA is disabled or no method's dependency is satisfied — what status
// and enrollment-required responses report to clients.
func (s *Engine) TwoFactorAllowedMethods() []string {
	out := []string{}
	for _, m := range []iam.TwoFactorMethod{iam.TwoFactorEmail, iam.TwoFactorSMS, iam.TwoFactorTOTP} {
		if s.TwoFactorMethodAvailable(string(m)) {
			out = append(out, string(m))
		}
	}
	return out
}
