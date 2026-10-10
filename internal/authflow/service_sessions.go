package authflow

import (
	"slices"
	"strings"
	"time"

	"github.com/open-rails/authkit/iam"
)

const SensitiveActionFreshAuthWindow = 15 * time.Minute

// RecentSignIn reports whether a token's assurance clears the sensitive-action
// gate: signed in within SensitiveActionFreshAuthWindow and, for an account
// with a usable second factor (mfa), with that factor (amr otp or mfa). An
// account without one is never blocked for lacking it.
func RecentSignIn(authTime time.Time, amr []string, mfa bool, now time.Time) bool {
	if authTime.IsZero() || authTime.After(now) || now.Sub(authTime) > SensitiveActionFreshAuthWindow {
		return false
	}
	return !mfa || slices.ContainsFunc(amr, func(m string) bool {
		m = strings.ToLower(strings.TrimSpace(m))
		return m == "otp" || m == "mfa"
	})
}

type SessionFreshness struct {
	LastAuthenticatedAt           time.Time
	TimeUntilStepUpRequired       time.Duration
	StepUpRequiredForSensitiveOps bool
	AuthMethods                   []string
	// MFAAuthenticatedAt is when the session last proved a second factor.
	MFAAuthenticatedAt time.Time
	// DPoPKey is the thumbprint of the DPoP key the session is bound to; ""
	// for a bearer session.
	DPoPKey string
}

// AssuranceClaims are the token's auth_time, amr and acr. A token claims
// otp/mfa only as of the session's last MFA proof. For an account with a
// second factor (secondFactor), auth_time is that proof, so a password re-auth
// never makes it fresh, and a session that never proved it claims no MFA. For
// an account without one (passkeys only), a later re-auth without MFA is fresh
// but no longer MFA (P5).
func (f SessionFreshness) AssuranceClaims(secondFactor bool) (authTime int64, amr []string, acr string) {
	amr = NormalizeAuthMethods(f.AuthMethods)
	at := f.LastAuthenticatedAt
	switch {
	case secondFactor && !f.MFAAuthenticatedAt.IsZero():
		at = f.MFAAuthenticatedAt
	case secondFactor || !f.MFAAuthenticatedAt.IsZero() && f.MFAAuthenticatedAt.Before(f.LastAuthenticatedAt):
		amr = slices.DeleteFunc(amr, func(m string) bool { return m == "otp" || m == "mfa" })
	}
	acr = iam.AssuranceLevelPassword
	for _, method := range amr {
		if method == "otp" || method == "mfa" {
			acr = iam.AssuranceLevelMFA
			break
		}
	}
	return at.Unix(), amr, acr
}

func NormalizeAuthMethods(methods []string) []string {
	seen := map[string]struct{}{}
	out := make([]string, 0, len(methods))
	for _, method := range methods {
		method = strings.ToLower(strings.TrimSpace(method))
		if method == "" {
			continue
		}
		if _, ok := seen[method]; ok {
			continue
		}
		seen[method] = struct{}{}
		out = append(out, method)
	}
	if len(out) == 0 {
		return []string{"pwd"}
	}
	return out
}
