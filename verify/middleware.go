package verify

import (
	"encoding/json"
	"net/http"
	"strings"
	"time"
)

// Required validates the Bearer token (JWT), enforces iss/aud/exp, and stores claims in request context.
func Required(v *Verifier) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			tokenStr := bearerToken(r.Header.Get("Authorization"))
			if tokenStr == "" {
				unauthorized(w, "missing_token")
				return
			}

			// API-key branch, BEFORE JWT verification.
			// If the bearer token carries the configured API-key marker it is
			// resolved against the DB as an API-key principal; a shaped-but-invalid
			// API key is rejected here rather than mistakenly re-tried as a JWT. The
			// password-login rate limiter lives on a different code path, so API keys
			// bypass it by design. API-key principals carry no UserID, so the
			// live-user enrichment/ban gate below is skipped for them.
			if scl, matched, serr := v.resolveAPIKey(r.Context(), tokenStr); matched {
				if serr != nil {
					unauthorized(w, serr.Error())
					return
				}
				r = r.WithContext(applyRequestContext(SetClaims(r.Context(), scl)))
				next.ServeHTTP(w, r)
				return
			}

			cl, err := v.Verify(tokenStr)
			if err != nil {
				unauthorized(w, err.Error())
				return
			}
			if cl.TwoFAEnrollment && !allowed2FAEnrollmentPath(r.Method, r.URL.Path) {
				forbidden(w, "forbidden")
				return
			}
			if v.enrich != nil && cl.IsDelegated() {
				// Fail-closed issuer gate (#78): resolve the remote_application by
				// the VALIDATED issuer and reject unknown/disabled ones. READ-ONLY
				// — no per-request write. Auth rides entirely on the token.
				ra, err := v.enrich.GetRemoteApplication(r.Context(), cl.Issuer)
				if err != nil || ra == nil || !ra.Enabled {
					unauthorized(w, "invalid_token")
					return
				}
			}

			// Best-effort DB enrichment when a service is attached. Skipped for
			// delegated principals: their subject does not exist locally, so the
			// local-user enrichment + the IsUserAllowed gate must not apply (the
			// resource server authorizes by issuer trust instead). A delegated
			// token carries no `sub`, so UserID is empty anyway — this is the
			// explicit guard.
			if v.enrich != nil && cl.UserID != "" && !cl.IsDelegated() {
				// Discord username enrichment.
				if du, err := v.enrich.GetProviderUsername(r.Context(), cl.UserID, "discord"); err == nil && du != "" {
					cl.DiscordUsername = du
				}

				// Role enrichment: if a non-delegated token carries no roles,
				// supply the user's canonical roles.
				if len(cl.Roles) == 0 {
					if rs := v.enrich.ListRoleSlugsByUser(r.Context(), cl.UserID); len(rs) > 0 {
						cl.Roles = rs
					}
				}

				// Email enrichment: if token has no email claim, try canonical email from DB.
				if cl.Email == "" {
					if e, err := v.enrich.GetEmailByUserID(r.Context(), cl.UserID); err == nil && strings.TrimSpace(e) != "" {
						cl.Email = e
					}
				}

				// Live user gate (ban/deleted).
				allowed, err := v.enrich.IsUserAllowed(r.Context(), cl.UserID)
				if err != nil || !allowed {
					unauthorized(w, "user_disabled")
					return
				}
			}

			r = r.WithContext(applyRequestContext(SetClaims(r.Context(), cl)))
			next.ServeHTTP(w, r)
		})
	}
}

func allowed2FAEnrollmentPath(method, path string) bool {
	path = strings.TrimRight(path, "/")
	return (method == http.MethodGet || method == http.MethodPost) &&
		(strings.HasSuffix(path, "/user/2fa") || path == "/user/2fa")
}

// Optional validates when Authorization is present; otherwise passes through.
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

func RequireFreshAuth(maxAge time.Duration) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			cl, err := GetClaims(r.Context())
			if err != nil || !isUserClaims(cl) || !cl.AuthenticatedWithin(maxAge) {
				forbidden(w, "forbidden")
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

func RequireAMR(method string) func(http.Handler) http.Handler {
	method = strings.TrimSpace(method)
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			cl, err := GetClaims(r.Context())
			if err != nil || !isUserClaims(cl) || method == "" || !cl.HasAMR(method) {
				forbidden(w, "forbidden")
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

func RequireACR(level string) func(http.Handler) http.Handler {
	level = strings.TrimSpace(level)
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			cl, err := GetClaims(r.Context())
			if err != nil || !isUserClaims(cl) || level == "" || !strings.EqualFold(strings.TrimSpace(cl.ACR), level) {
				forbidden(w, "forbidden")
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

func isUserClaims(cl Claims) bool {
	return strings.TrimSpace(cl.UserID) != "" && !cl.IsAPIKey() && !cl.IsRemoteApplication() && !cl.IsDelegated()
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
