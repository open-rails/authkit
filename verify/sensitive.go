package verify

import (
	"net/http"
	"strings"
	"time"
)

const DefaultSensitiveMaxAge = 15 * time.Minute

type SensitiveOptions struct {
	MaxAge        time.Duration
	RequireMFA    bool
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
				writeErrData(w, http.StatusForbidden, "step_up_required", sensitiveMetadata(opts))
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
	hasMFA := cl.HasAMR("otp") || cl.HasAMR("mfa")
	if opts.RequireMFA && !hasMFA {
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

func sensitiveMetadata(opts SensitiveOptions) map[string]any {
	methods := opts.StepUpMethods
	if len(methods) == 0 {
		methods = []string{"password", "2fa"}
	}
	out := map[string]any{
		"step_up_methods": methods,
		"max_age_seconds": int64(opts.MaxAge.Seconds()),
	}
	if opts.RequireMFA {
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
