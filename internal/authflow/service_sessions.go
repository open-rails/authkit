package authflow

import (
	"slices"
	"strings"
	"time"

	"github.com/open-rails/authkit/iam"
)

const SensitiveActionFreshAuthWindow = 15 * time.Minute

type SessionFreshness struct {
	LastAuthenticatedAt           time.Time
	TimeUntilStepUpRequired       time.Duration
	StepUpRequiredForSensitiveOps bool
	AuthMethods                   []string
	// MFAAuthenticatedAt is when the session last proved a second factor.
	MFAAuthenticatedAt time.Time
}

// AssuranceClaims are the token's auth_time, amr and acr. For an account with
// a second factor (secondFactor), auth_time is when the session last proved
// that factor, so a password re-auth never makes it fresh; a session that
// never proved it carries no otp/mfa method.
func (f SessionFreshness) AssuranceClaims(secondFactor bool) (authTime int64, amr []string, acr string) {
	amr = NormalizeAuthMethods(f.AuthMethods)
	at := f.LastAuthenticatedAt
	if secondFactor {
		if f.MFAAuthenticatedAt.IsZero() {
			amr = slices.DeleteFunc(amr, func(m string) bool { return m == "otp" || m == "mfa" })
		} else {
			at = f.MFAAuthenticatedAt
		}
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
