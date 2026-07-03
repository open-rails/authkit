package authcore

import (
	"errors"
	"strings"
)

// Two-factor policy gating (#148). Mode/Methods from TwoFactorConfig decide which
// second factors can be enrolled, challenged, and verified. Disabled turns the
// whole flow off; otherwise only configured methods whose delivery dependency is
// present are usable (fail closed when a dependency — SMS sender, email sender, or
// TOTP key — is missing). These guard the core operations, so EVERY caller (HTTP
// handlers and direct embedders) is gated at one chokepoint.

// Err2FAMethodUnavailable is returned by 2FA enroll/challenge operations when the
// method is disabled by policy or its delivery dependency is missing.
var Err2FAMethodUnavailable = errors.New("2fa_method_unavailable")

// TwoFactorEnabled reports whether any 2FA flow is usable (Mode != Disabled).
func (s *Service) TwoFactorEnabled() bool {
	return normalizeTwoFactorMode(s.cfg.TwoFactor.Mode) != TwoFactorDisabled
}

func (s *Service) twoFactorMethodConfigured(m TwoFactorMethod) bool {
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
func (s *Service) TwoFactorMethodAvailable(method string) bool {
	m := TwoFactorMethod(strings.ToLower(strings.TrimSpace(method)))
	if !s.twoFactorMethodConfigured(m) {
		return false
	}
	switch m {
	case TwoFactorSMS:
		return s.SMSAvailable()
	case TwoFactorEmail:
		return s.email != nil
	case TwoFactorTOTP:
		return len(s.cfg.TwoFactor.TOTPSecretKey) > 0
	default:
		return false
	}
}

// TwoFactorAllowedMethods is the set of currently-usable methods, in stable order.
// Empty when 2FA is disabled or no method's dependency is satisfied — what status
// and enrollment-required responses report to clients.
func (s *Service) TwoFactorAllowedMethods() []string {
	out := []string{}
	for _, m := range []TwoFactorMethod{TwoFactorEmail, TwoFactorSMS, TwoFactorTOTP} {
		if s.TwoFactorMethodAvailable(string(m)) {
			out = append(out, string(m))
		}
	}
	return out
}
