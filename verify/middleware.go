package verify

import (
	"encoding/json"
	"errors"
	"net/http"
	"strings"

	authkit "github.com/open-rails/authkit"
)

// unauthorizedError is the 401 an out-of-band verification failure becomes:
// an *authkit.Error keeps its own code and status; anything else is
// invalid_token. VerifyRequest returns it and both Required (which writes it)
// and out-of-band callers (which inspect err != nil) share one pipeline.
func unauthorizedError(err error) error {
	if e := authkit.AsError(err); e != nil {
		return err
	}
	return authkit.E(authkit.CodeInvalidToken, authkit.WithCause(err))
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
// That statelessness is now an explicit OPT-OUT, not the only option (#267): a
// privileged surface that cannot accept the residual window calls
// VerifyRequestLive (or mounts RequiredLive) and gets the same pipeline plus a
// per-request account-liveness gate and fresh identity claims. Choose this one
// deliberately — for genuinely stateless verifiers, and for read paths where a
// ≤1-TTL window is acceptable.
func (v *Verifier) VerifyRequest(r *http.Request) (Claims, error) {
	tokenStr := requestToken(r)
	if tokenStr == "" {
		return Claims{}, authkit.E(authkit.CodeMissingToken, authkit.WithStatus(http.StatusUnauthorized))
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
		return Claims{}, authkit.E(authkit.CodeForbidden, authkit.WithStatus(http.StatusForbidden))
	}
	// #148: per-request forced-enrollment gate. When 2FA policy is Required, a
	// native user whose token shows they are not yet enrolled (mfa_enrolled absent)
	// is blocked from everything except the 2FA enroll/challenge routes — so an
	// existing un-enrolled user is challenged on their NEXT authenticated request,
	// not just at signup. Gated explicitly on IsUser: API-key/delegated/service
	// principals can't enroll TOTP and bypass (note d).
	if v.requireMFAEnrollment && cl.IsUser() && !cl.MFAEnrolled && !v.mfaEnrollmentExemptPath(r.Method, r.URL.Path) {
		return Claims{}, authkit.E(authkit.CodeTwoFAEnrollmentRequired, authkit.WithStatus(http.StatusForbidden))
	}

	return cl, nil
}

func writeRequestError(w http.ResponseWriter, r *http.Request, err error) {
	if errors.Is(err, errDPoPProofRequired) || (isDPoPRequest(r) && errors.Is(err, ErrSenderProofRequired)) {
		w.Header().Set("WWW-Authenticate", `DPoP error="invalid_dpop_proof", algs="ES256"`)
	}
	authkit.WriteError(w, unauthorizedError(err))
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

// SetMFAEnrollmentExemptPaths installs the set of route paths that stay
// reachable to a request blocked by the requireMFAEnrollment gate or carrying a
// TwoFAEnrollment-only token (#243): the 2FA enroll/challenge/verify surface.
// AuthKit's server derives this set from its authoritative route registry
// (authhttp.RouteSpec.MFAEnrollmentExempt) at construction, so a renamed or
// added enroll route can't silently drift out of the allowlist. A Verifier that
// never calls this (verify-only, no WithRequireMFAEnrollment) exempts nothing.
// Paths are suffix-matched against the incoming request path, since AuthKit
// routes are prefix-neutral (a host may mount them under any prefix).
func (v *Verifier) SetMFAEnrollmentExemptPaths(paths []string) *Verifier {
	m := make(map[string]bool, len(paths))
	for _, p := range paths {
		p = strings.TrimRight(strings.TrimSpace(p), "/")
		if p != "" {
			m[p] = true
		}
	}
	v.mfaEnrollmentExemptPaths = m
	return v
}

// AddMFAEnrollmentExemptRoutes registers ANCHORED exempt paths (mount prefix +
// route path), matched exactly. authhttp.MountHandler calls it with the prefix
// it mounted under; once any anchored route is registered the suffix match of
// SetMFAEnrollmentExemptPaths is no longer consulted, so a host route that
// merely ends in "/user/2fa" cannot be reached with an enrollment-only token
// (ak#324). The suffix form remains for verify-only consumers that never mount.
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
// user must still reach. See SetMFAEnrollmentExemptPaths / AddMFAEnrollmentExemptRoutes.
func (v *Verifier) mfaEnrollmentExemptPath(method, path string) bool {
	if method != http.MethodGet && method != http.MethodPost && method != http.MethodDelete {
		return false
	}
	path = strings.TrimRight(path, "/")
	v.mu.RLock()
	anchored, exact := len(v.mfaEnrollmentExemptRoutes) > 0, v.mfaEnrollmentExemptRoutes[path]
	v.mu.RUnlock()
	if anchored {
		return exact
	}
	if len(v.mfaEnrollmentExemptPaths) == 0 {
		return false
	}
	for suffix := range v.mfaEnrollmentExemptPaths {
		if path == suffix || strings.HasSuffix(path, suffix) {
			return true
		}
	}
	return false
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
