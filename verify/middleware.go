package verify

import (
	"encoding/json"
	"errors"
	"net/http"
	"strings"

	"github.com/open-rails/authkit/iam"
	"github.com/open-rails/authkit/internal/errmodel"
)

// unauthorizedError is the 401 an out-of-band verification failure becomes:
// an AuthKit error keeps its own code; anything else is invalid_token. VerifyRequest returns it and both Required (which writes it)
// and out-of-band callers (which inspect err != nil) share one pipeline.
func unauthorizedError(err error) error {
	if errmodel.As(err) != nil {
		return err
	}
	return errmodel.E(errmodel.CodeInvalidToken, errmodel.WithCause(err))
}

// VerifyRequest runs the full Required authentication pipeline — bearer parse,
// API-key resolution, typed JWT verification and the 2FA gate — and returns
// claims without writing a response. Issuer eligibility and delegated authority
// are enforced by the shared verifier on every typed entrypoint.
// Embedders that authenticate a request outside the middleware chain call this
// instead of driving Required against a throwaway ResponseWriter. The
// native-user path is stateless: it does ZERO DB lookups (#215) — no ban gate,
// no role/email/provider re-enrichment. Ban/deleted is enforced at token mint
// (login + refresh); the short access TTL bounds the residual window (#90).
//
// Per-request account liveness is opt-in (#267): a surface that cannot accept
// the residual window calls VerifyRequestLive (or mounts RequiredLive) for an
// account-liveness gate and fresh identity claims. This default path stays
// stateless even when a liveness source has been configured.
func (v *Verifier) VerifyRequest(r *http.Request) (Claims, error) {
	tokenStr := requestToken(r)
	if tokenStr == "" {
		return Claims{}, errmodel.E(errmodel.CodeUnauthenticated)
	}

	// API-key branch, BEFORE JWT verification. A shaped-but-invalid API key is
	// rejected here rather than re-tried as a JWT. resolveAPIKey does its own
	// live secret resolution; it does not flow into the stateless JWT path below.
	if scl, matched, serr := v.resolveAPIKey(r.Context(), tokenStr); matched {
		if isDPoPRequest(r) {
			return Claims{}, ErrSenderProofRequired
		}
		if serr != nil {
			return Claims{}, unauthorizedError(serr)
		}
		return scl, nil
	}

	cl, err := v.verify(r.Context(), tokenStr, r)
	if err != nil {
		return Claims{}, unauthorizedError(err)
	}
	if cl.TwoFAEnrollment && !v.mfaEnrollmentExemptPath(r.Method, r.URL.Path) {
		return Claims{}, errmodel.E(errmodel.CodeForbidden)
	}
	// #148: per-request forced-enrollment gate. When 2FA policy is Required, a
	// native user whose token shows they are not yet enrolled (mfa_enrolled absent)
	// is blocked from everything except the 2FA enroll/challenge routes — so an
	// existing un-enrolled user is challenged on their NEXT authenticated request,
	// not just at signup. Gated explicitly on IsUser: API-key/delegated/service
	// principals can't enroll TOTP and bypass (note d).
	if v.requireMFAEnrollment && cl.IsUser() && !cl.MFAEnrolled && !v.mfaEnrollmentExemptPath(r.Method, r.URL.Path) {
		return Claims{}, errmodel.E(errmodel.CodeTwoFAEnrollmentRequired)
	}

	return cl, nil
}

func writeRequestError(w http.ResponseWriter, r *http.Request, err error) {
	if errors.Is(err, errDPoPProofRequired) || (isDPoPRequest(r) && errors.Is(err, ErrSenderProofRequired)) {
		w.Header().Set("WWW-Authenticate", `DPoP error="invalid_dpop_proof", algs="ES256"`)
	}
	iam.WriteError(w, unauthorizedError(err))
}

// Required validates the Bearer token (JWT), enforces iss/aud/exp, and stores claims in request context.
// Gin hosts: use the gin-native authkitgin.Required (adapters/gin) instead of hand-wrapping this.
func Required(v *Verifier) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			cl, err := v.VerifyRequest(r)
			if err != nil {
				writeRequestError(w, r, err)
				return
			}
			r = r.WithContext(SetClaims(r.Context(), cl))
			next.ServeHTTP(w, r)
		})
	}
}

// AddMFAEnrollmentExemptRoutes registers ANCHORED exempt paths (mount prefix +
// route path), matched exactly; AuthKit's mount registers its own. A host
// route that merely ends in "/user/2fa" cannot be reached with an
// enrollment-only token (ak#324).
func (v *Verifier) AddMFAEnrollmentExemptRoutes(paths []string) *Verifier {
	v.mu.Lock()
	defer v.mu.Unlock()
	if v.mfaEnrollmentExemptRoutes == nil {
		v.mfaEnrollmentExemptRoutes = map[string]bool{}
	}
	for _, p := range paths {
		if p = strings.TrimRight(strings.TrimSpace(p), "/"); p != "" {
			v.mfaEnrollmentExemptRoutes[p] = true
		}
	}
	return v
}

// mfaEnrollmentExemptPath reports whether a path is one a forced-enrollment-gated
// user must still reach. See AddMFAEnrollmentExemptRoutes.
func (v *Verifier) mfaEnrollmentExemptPath(method, path string) bool {
	if method != http.MethodGet && method != http.MethodPost && method != http.MethodDelete {
		return false
	}
	path = strings.TrimRight(path, "/")
	v.mu.RLock()
	defer v.mu.RUnlock()
	return v.mfaEnrollmentExemptRoutes[path]
}

// Optional validates when Authorization is present; otherwise passes through.
// Gin hosts: use the gin-native authkitgin.Optional (adapters/gin) instead of hand-wrapping this.
func Optional(v *Verifier) func(http.Handler) http.Handler {
	req := Required(v)
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Header.Get("Authorization") == "" {
				next.ServeHTTP(w, r)
				return
			}
			req(next).ServeHTTP(w, r)
		})
	}
}

func isUserClaims(cl Claims) bool {
	return cl.IsUser()
}

func toUnix(v any) (int64, bool) {
	switch t := v.(type) {
	case float64:
		return int64(t), true
	case int64:
		return t, true
	case json.Number:
		i, err := t.Int64()
		return i, err == nil
	}
	return 0, false
}
