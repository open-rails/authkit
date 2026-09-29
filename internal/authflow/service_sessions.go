package authflow

import (
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
}

func (f SessionFreshness) AssuranceClaims() (authTime int64, amr []string, acr string) {
	amr = NormalizeAuthMethods(f.AuthMethods)
	acr = iam.AssuranceLevelPassword
	for _, method := range amr {
		if method == "otp" || method == "mfa" {
			acr = iam.AssuranceLevelMFA
			break
		}
	}
	return f.LastAuthenticatedAt.Unix(), amr, acr
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
