package verify

import (
	"encoding/json"
	"errors"
	"net/http"
	"strings"
)

// authError carries the HTTP status + reason a verification failure would have
// written, so VerifyRequest can return it and both Required (which writes it) and
// out-of-band callers (which inspect err != nil) share one pipeline.
type authError struct {
	status int
	reason string
}

func (e *authError) Error() string { return e.reason }

// VerifyRequest runs the full Required authentication pipeline — bearer parse,
// API-key resolution, JWT verify, 2FA gate, and (for delegated principals) the
// fail-closed issuer gate — and returns the claims WITHOUT writing a response.
// Embedders that authenticate a request outside the middleware chain call this
// instead of driving Required against a throwaway ResponseWriter. The
// native-user path is stateless: it does ZERO DB lookups (#215) — no ban gate,
// no role/email/provider re-enrichment. Ban/deleted is enforced at token mint
// (login + refresh); the short access TTL bounds the residual window (#90).
func (v *Verifier) VerifyRequest(r *http.Request) (Claims, error) {
	tokenStr := bearerToken(r.Header.Get("Authorization"))
	if tokenStr == "" {
		return Claims{}, &authError{http.StatusUnauthorized, "missing_token"}
	}

	// API-key branch, BEFORE JWT verification. A shaped-but-invalid API key is
	// rejected here rather than re-tried as a JWT. resolveAPIKey does its own
	// live secret resolution; it does not flow into the stateless JWT path below.
	if scl, matched, serr := v.resolveAPIKey(r.Context(), tokenStr); matched {
		if serr != nil {
			return Claims{}, &authError{http.StatusUnauthorized, serr.Error()}
		}
		return scl, nil
	}

	cl, err := v.Verify(tokenStr)
	if err != nil {
		return Claims{}, &authError{http.StatusUnauthorized, err.Error()}
	}
	if cl.TwoFAEnrollment && !allowed2FAEnrollmentPath(r.Method, r.URL.Path) {
		return Claims{}, &authError{http.StatusForbidden, "forbidden"}
	}
	// #148: per-request forced-enrollment gate. When 2FA policy is Required, a
	// native user whose token shows they are not yet enrolled (mfa_enrolled absent)
	// is blocked from everything except the 2FA enroll/challenge routes — so an
	// existing un-enrolled user is challenged on their NEXT authenticated request,
	// not just at signup. Gated explicitly on IsUser: API-key/delegated/service
	// principals can't enroll TOTP and bypass (note d).
	if v.requireMFAEnrollment && cl.IsUser() && !cl.MFAEnrolled && !allowed2FAEnrollmentPath(r.Method, r.URL.Path) {
		return Claims{}, &authError{http.StatusForbidden, "2fa_enrollment_required"}
	}
	if v.enrich != nil && cl.isDelegated() {
		// Fail-closed issuer gate (#78): resolve remote_application by the
		// VALIDATED issuer, reject unknown/disabled. READ-ONLY.
		ra, err := v.enrich.GetRemoteApplication(r.Context(), cl.Issuer)
		if err != nil || ra == nil || !ra.Enabled {
			return Claims{}, &authError{http.StatusUnauthorized, "invalid_token"}
		}
	}

	// #215: the native-user request path is STATELESS — zero DB lookups. We do
	// NOT re-enrich roles/email/discord and do NOT run a per-request ban/deleted
	// gate here. Ban/deleted is enforced where NEW tokens are minted — login
	// (ensureUserAccess) and refresh (ExchangeRefreshToken → ensureUserAccessByID
	// + IsUserAllowed, revoking all sessions on disable) — so a banned/deleted
	// user cannot obtain a new access token and their existing one expires within
	// one access-TTL window (≤15min by default). That residual window is the
	// accepted #90 trade-off (internal/authcore/service.go:348-352: trust the
	// short-lived access token instead of a per-request liveness lookup). Roles
	// resolve lazily via Can() on permission-gated routes (DB-live there); email
	// rides in the token claims. Delegated principals are still gated above.
	return cl, nil
}

// Required validates the Bearer token (JWT), enforces iss/aud/exp, and stores claims in request context.
// Gin hosts: use the gin-native authkitgin.Required (adapters/gin) instead of hand-wrapping this.
func Required(v *Verifier) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			cl, err := v.VerifyRequest(r)
			if err != nil {
				var ae *authError
				if errors.As(err, &ae) && ae.status == http.StatusForbidden {
					forbidden(w, ae.reason)
				} else {
					unauthorized(w, err.Error())
				}
				return
			}
			r = r.WithContext(applyRequestContext(SetClaims(r.Context(), cl)))
			next.ServeHTTP(w, r)
		})
	}
}

// allowed2FAEnrollmentPath reports whether a path is one a forced-enrollment-gated
// user must still reach: the 2FA enroll surface (/user/2fa[/...]) and the
// challenge/verify surface (/2fa/challenge, /2fa/verify). Matching by route suffix
// keeps the verify layer free of the route table; the canonical 2FA route set
// lives in http/routes.go and any addition there must stay covered here.
// ponytail: suffix allowlist, not derived from the live route registry — upgrade
// to registry-derived only if the 2FA route paths ever stop being stable suffixes.
func allowed2FAEnrollmentPath(method, path string) bool {
	if method != http.MethodGet && method != http.MethodPost && method != http.MethodDelete {
		return false
	}
	path = strings.TrimRight(path, "/")
	for _, suffix := range []string{"/user/2fa", "/user/2fa/backup-codes", "/2fa/challenge", "/2fa/verify"} {
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
			if bearerToken(r.Header.Get("Authorization")) == "" {
				next.ServeHTTP(w, r)
				return
			}
			req(next).ServeHTTP(w, r)
		})
	}
}

// RequiredUser authenticates a native human user and rejects machine/delegated principals.
func RequiredUser(v *Verifier) func(http.Handler) http.Handler {
	req := Required(v)
	return func(next http.Handler) http.Handler {
		return req(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			cl, err := GetClaims(r.Context())
			if err != nil || !cl.IsUser() {
				unauthorized(w, "invalid_principal")
				return
			}
			next.ServeHTTP(w, r)
		}))
	}
}

// OptionalUser enriches a request with native-user claims when present; machine
// or invalid credentials fall through as anonymous.
func OptionalUser(v *Verifier) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if bearerToken(r.Header.Get("Authorization")) == "" {
				next.ServeHTTP(w, r)
				return
			}
			cl, err := v.VerifyRequest(r)
			if err != nil || !cl.IsUser() {
				next.ServeHTTP(w, r)
				return
			}
			r = r.WithContext(applyRequestContext(SetClaims(r.Context(), cl)))
			next.ServeHTTP(w, r)
		})
	}
}

// RequireEntitlement gates a handler on the presence of a single entitlement in
// the verified claims (case-insensitive, see Claims.HasEntitlement). It must run
// after Required so claims are present. API-key principals and delegated
// tokens carry no entitlements and are therefore denied.
func RequireEntitlement(ent string) func(http.Handler) http.Handler {
	return RequireAnyEntitlement(ent)
}

// RequireAnyEntitlement gates a handler on the presence of at least one of the
// given entitlements. With no entitlements listed it denies all requests
// (fail-closed). It must run after Required.
func RequireAnyEntitlement(ents ...string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			cl, err := GetClaims(r.Context())
			if err != nil {
				forbidden(w, "forbidden")
				return
			}
			for _, ent := range ents {
				if strings.TrimSpace(ent) != "" && cl.HasEntitlement(ent) {
					next.ServeHTTP(w, r)
					return
				}
			}
			forbidden(w, "forbidden")
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
