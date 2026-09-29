package verify

import (
	"context"
	"net/http"

	"github.com/open-rails/authkit/iam"
)

// SessionChecker checks the sign-in behind verified claims, live;
// *authkit.Client is one.
type SessionChecker interface {
	// CheckRecentSignIn returns nil when the session or device key cl was
	// minted from is still active and signed in recently enough for a
	// sensitive action, with its second factor when the account has one.
	// Otherwise it returns the error to answer: iam.ErrSessionRevoked,
	// step_up_required carrying the step-up methods, or forbidden for a
	// credential that is not a user's.
	CheckRecentSignIn(ctx context.Context, cl Claims) error
}

// Sensitive authenticates the request (it includes Required) and gates it on
// the gate AuthKit's own credential routes apply: the session or device key
// behind the token is still active (not logged out, revoked, banned or
// deleted) and signed in within the last 15 minutes, with its second factor
// when the account has one. A stale sign-in answers 403 step_up_required with
// the account's step-up methods, which auth-ui handles; a revoked one 401
// session_revoked. Stack it after RequirePermission when a route needs both.
func Sensitive(a Authority) func(http.Handler) http.Handler {
	authenticate := Required(a.Verifier())
	return func(next http.Handler) http.Handler {
		gate := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			cl, err := GetClaims(r.Context())
			if err == nil {
				err = a.CheckRecentSignIn(r.Context(), cl)
			}
			if err != nil {
				iam.WriteError(w, err)
				return
			}
			next.ServeHTTP(w, r)
		})
		return authenticate(gate)
	}
}
