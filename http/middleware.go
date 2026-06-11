package authhttp

import (
	"encoding/json"
	"net/http"
	"strings"

	"github.com/jackc/pgx/v5/pgxpool"
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

			// Service Token (service token) branch, BEFORE JWT verification.
			// If the bearer token carries the configured service-token marker it is
			// resolved against the DB as a service principal; a shaped-but-invalid
			// service token is rejected here rather than mistakenly re-tried as a JWT. The
			// password-login rate limiter lives on a different code path, so service tokens
			// bypass it by design. Service principals carry no UserID, so the
			// live-user enrichment/ban gate below is skipped for them.
			if scl, matched, serr := v.resolveServiceToken(r.Context(), tokenStr); matched {
				if serr != nil {
					unauthorized(w, serr.Error())
					return
				}
				r = r.WithContext(setClaims(r.Context(), scl))
				next.ServeHTTP(w, r)
				return
			}

			cl, err := v.Verify(tokenStr)
			if err != nil {
				unauthorized(w, err.Error())
				return
			}
			if v.enrich != nil && cl.IsDelegated() {
				if _, err := v.enrich.TouchTenantSubject(r.Context(), cl.TenantID, cl.Tenant, cl.Issuer, cl.DelegatedSubject); err != nil {
					unauthorized(w, "invalid_token")
					return
				}
			}

			// Best-effort DB enrichment when a service is attached. Skipped for
			// delegated platform principals: their subject is a tenant user
			// that does not exist locally, so the local-user enrichment + the
			// IsUserAllowed gate must not apply (the resource server authorizes
			// by tenant/issuer trust instead). A delegated token carries no
			// `sub`, so UserID is empty anyway — this is the explicit guard.
			if v.enrich != nil && cl.UserID != "" && !cl.IsDelegated() {
				// Discord username enrichment.
				if du, err := v.enrich.GetProviderUsername(r.Context(), cl.UserID, "discord"); err == nil && du != "" {
					cl.DiscordUsername = du
				}

				// (issue 60) Role enrichment: if a non-delegated token carries no roles,
				// supply the user's canonical global roles. No tenant-mode gate; a
				// tenant-scoped token already carries tenant roles so this won't fire.
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

			r = r.WithContext(setClaims(r.Context(), cl))
			next.ServeHTTP(w, r)
		})
	}
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

// RequireAdmin verifies admin role directly in Postgres.
func RequireAdmin(pg *pgxpool.Pool) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if pg == nil {
				forbidden(w, "forbidden")
				return
			}
			cl, err := getClaims(r.Context())
			if err != nil || cl.UserID == "" {
				forbidden(w, "forbidden")
				return
			}
			isAdmin, err := IsAdmin(r.Context(), pg, cl.UserID)
			if err == nil && isAdmin {
				next.ServeHTTP(w, r)
				return
			}
			forbidden(w, "forbidden")
		})
	}
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
