package engine

import (
	"fmt"
	"log/slog"
	"path/filepath"
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

// twoFactorMethodAvailable reports whether a second-factor method can be
// enrolled/used right now: enabled by policy AND its delivery dependency present.
func (s *Engine) twoFactorMethodAvailable(method string) bool {
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

// TwoFactorMethods are the second factors a user can enroll now, in stable
// order: enabled by TwoFactor.Mode and Methods, with their dependency present
// (Deps.Email, Deps.SMS and its latest health check, the TOTP key). Empty when
// 2FA is disabled.
func (s *Engine) TwoFactorMethods() []iam.TwoFactorMethod {
	out := []iam.TwoFactorMethod{}
	for _, m := range []iam.TwoFactorMethod{iam.TwoFactorEmail, iam.TwoFactorSMS, iam.TwoFactorTOTP} {
		if s.twoFactorMethodAvailable(string(m)) {
			out = append(out, m)
		}
	}
	return out
}

// TwoFactorAllowedMethods is TwoFactorMethods as the strings the
// allowed_methods wire fields carry.
func (s *Engine) TwoFactorAllowedMethods() []string {
	methods := s.TwoFactorMethods()
	out := make([]string, len(methods))
	for i, m := range methods {
		out[i] = string(m)
	}
	return out
}

// requireEnrollableSecondFactor refuses, at New, a deployment where someone
// must hold MFA but no second factor can be enrolled: its operators could
// never enroll one or reach admin. A missing TOTP key is only a warning when
// no one needs MFA or another method works. An engine that signs no one in
// (Keys.VerifyOnly) has nothing to enroll.
func (s *Engine) requireEnrollableSecondFactor(signs bool) error {
	if !s.TwoFactorEnabled() || !signs {
		return nil
	}
	totpKeyMissing := s.twoFactorMethodConfigured(iam.TwoFactorTOTP) && len(s.cfg.TwoFactor.TOTPSecretKey) == 0
	totpKeyPath := filepath.Join(totpKeysDir(s.cfg), totpKeyFilename)
	var need string
	if len(s.TwoFactorMethods()) == 0 {
		switch roles := s.mfaRequiredRoles(); {
		case s.requireMFAEnrollment():
			need = "TwoFactor.Mode is required, so every account needs MFA"
		case len(roles) == 1:
			need = "role " + roles[0] + " needs MFA"
		case len(roles) > 1:
			need = "roles " + strings.Join(roles, ", ") + " need MFA"
		}
	}
	if need == "" {
		if totpKeyMissing {
			slog.Warn("authkit: TOTP is offered but has no key, so it is unavailable", "path", totpKeyPath)
		}
		return nil
	}
	var fixes []string
	if totpKeyMissing {
		fixes = append(fixes, fmt.Sprintf("put a 16, 24 or 32-byte key at %s (or set TwoFactor.TOTPSecretKey)", totpKeyPath))
	}
	if s.twoFactorMethodConfigured(iam.TwoFactorEmail) {
		fixes = append(fixes, "set Deps.Email")
	}
	if s.twoFactorMethodConfigured(iam.TwoFactorSMS) {
		fixes = append(fixes, "set Deps.SMS")
	}
	fixes = append(fixes, "set TwoFactor.Mode to disabled")
	return fmt.Errorf("authkit: %s, but no second factor can be enrolled: %s", need, strings.Join(fixes, ", or "))
}

// mfaRequiredRoles lists every role, in every persona, whose permissions need
// MFA.
func (s *Engine) mfaRequiredRoles() []string {
	schema := s.groupSchemaOrDefault()
	var out []string
	for _, persona := range schema.Personas() {
		roles, _ := schema.Roles(persona)
		for _, r := range roles {
			if r.RequiresMFA {
				out = append(out, r.Name.String())
			}
		}
	}
	return out
}
