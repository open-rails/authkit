package verify

import (
	"net/http"
	"strings"
	"time"
)

const DefaultSensitiveMaxAge = 15 * time.Minute

type SensitiveOptions struct {
	MaxAge        time.Duration
	AMR           []string
	ACR           string
	StepUpMethods []string
}

func Sensitive(options ...SensitiveOptions) func(http.Handler) http.Handler {
	opts := normalizeSensitiveOptions(options...)
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			cl, err := GetClaims(r.Context())
			if err != nil || !SensitiveClaims(cl, opts) {
				writeErrData(w, http.StatusForbidden, "step_up_required", sensitiveMetadata(opts, cl))
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

func SensitiveClaims(cl Claims, options ...SensitiveOptions) bool {
	opts := normalizeSensitiveOptions(options...)
	if !isUserClaims(cl) {
		return false
	}
	for _, method := range opts.AMR {
		if strings.TrimSpace(method) != "" && !cl.HasAMR(method) {
			return false
		}
	}
	if opts.ACR != "" && !strings.EqualFold(strings.TrimSpace(cl.ACR), opts.ACR) {
		return false
	}
	// MFA-if-enrolled (default, non-optional): a user with usable 2FA must step up
	// WITH 2FA — a password/OIDC re-auth is not sufficient. Users without 2FA are
	// never blocked here; forcing a user to HAVE 2FA is a provisioning concern
	// (role RequiresMFA / signup enrollment), not a step-up-gate concern, so the
	// gate can never lock anyone out.
	if cl.MFAEnrolled && !(cl.HasAMR("otp") || cl.HasAMR("mfa")) {
		return false
	}
	return cl.AuthenticatedWithin(opts.MaxAge)
}

func normalizeSensitiveOptions(options ...SensitiveOptions) SensitiveOptions {
	opts := SensitiveOptions{MaxAge: DefaultSensitiveMaxAge}
	if len(options) > 0 {
		opts = options[0]
		if opts.MaxAge <= 0 {
			opts.MaxAge = DefaultSensitiveMaxAge
		}
	}
	return opts
}

func sensitiveMetadata(opts SensitiveOptions, cl Claims) map[string]any {
	methods := opts.StepUpMethods
	if len(methods) == 0 {
		methods = []string{"password", "2fa"}
	}
	out := map[string]any{
		"step_up_methods": methods,
		"max_age_seconds": int64(opts.MaxAge.Seconds()),
	}
	// Per-user: a user with 2FA enrolled must satisfy the gate with 2FA, so tell
	// the client to route to a 2FA method (not a password step-up).
	if cl.MFAEnrolled {
		out["mfa_required"] = true
	}
	if len(opts.AMR) > 0 {
		out["required_amr"] = opts.AMR
	}
	if opts.ACR != "" {
		out["required_acr"] = opts.ACR
	}
	return out
}
