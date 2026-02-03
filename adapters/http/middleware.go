package authhttp

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"time"

	jwt "github.com/golang-jwt/jwt/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	core "github.com/open-rails/authkit/core"
)

// Required validates the Bearer token (JWT), enforces iss/aud/exp, and stores claims in request context.
func Required(svc core.Verifier) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			tokenStr := bearerToken(r.Header.Get("Authorization"))
			if tokenStr == "" {
				unauthorized(w, "missing_token")
				return
			}
			claims := jwt.MapClaims{}
			parser := jwt.NewParser(jwt.WithoutClaimsValidation())
			token, err := parser.ParseWithClaims(tokenStr, claims, svc.Keyfunc())
			if err != nil || !token.Valid {
				unauthorized(w, "invalid_token")
				return
			}

			iss, _ := claims["iss"].(string)

			// Verify-only mode: allow multiple issuers/audience rules.
			type acceptCfgProvider interface{ AcceptConfig() core.AcceptConfig }
			if ap, ok := svc.(acceptCfgProvider); ok && len(ap.AcceptConfig().Issuers) > 0 {
				accept := ap.AcceptConfig()
				var match *core.IssuerAccept
				for i := range accept.Issuers {
					if accept.Issuers[i].Issuer == iss {
						match = &accept.Issuers[i]
						break
					}
				}
				if match == nil {
					unauthorized(w, "bad_issuer")
					return
				}
				var audiences []string
				if len(match.Audiences) > 0 {
					audiences = match.Audiences
				} else if match.Audience != "" {
					audiences = []string{match.Audience}
				}
				if len(audiences) > 0 && !audContainsAny(claims["aud"], audiences) {
					unauthorized(w, "bad_audience")
					return
				}
				skew := accept.Skew
				if skew == 0 {
					skew = 60 * time.Second
				}
				expUnix, ok := toUnix(claims["exp"])
				if !ok {
					unauthorized(w, "missing_exp")
					return
				}
				if time.Unix(expUnix, 0).Before(time.Now().Add(-skew)) {
					unauthorized(w, "token_expired")
					return
				}
				if nbfUnix, ok := toUnix(claims["nbf"]); ok {
					if time.Now().Add(skew).Before(time.Unix(nbfUnix, 0)) {
						unauthorized(w, "invalid_token")
						return
					}
				}
				if iatUnix, ok := toUnix(claims["iat"]); ok {
					if time.Unix(iatUnix, 0).After(time.Now().Add(skew)) {
						unauthorized(w, "invalid_token")
						return
					}
				}
			} else {
				// Service-issued tokens: enforce single issuer/audience settings from Options.
				opts := svc.Options()
				if iss != opts.Issuer {
					unauthorized(w, "bad_issuer")
					return
				}
				switch {
				case len(opts.ExpectedAudiences) > 0:
					if !audContainsAny(claims["aud"], opts.ExpectedAudiences) {
						unauthorized(w, "bad_audience")
						return
					}
				case opts.ExpectedAudience != "":
					if !audContains(claims["aud"], opts.ExpectedAudience) {
						unauthorized(w, "bad_audience")
						return
					}
				}
				expUnix, ok := toUnix(claims["exp"])
				if !ok {
					unauthorized(w, "missing_exp")
					return
				}
				skew := time.Second
				if time.Unix(expUnix, 0).Before(time.Now().Add(-skew)) {
					unauthorized(w, "token_expired")
					return
				}
				if nbfUnix, ok := toUnix(claims["nbf"]); ok {
					if time.Now().Add(skew).Before(time.Unix(nbfUnix, 0)) {
						unauthorized(w, "invalid_token")
						return
					}
				}
				if iatUnix, ok := toUnix(claims["iat"]); ok {
					if time.Unix(iatUnix, 0).After(time.Now().Add(skew)) {
						unauthorized(w, "invalid_token")
						return
					}
				}
			}

			var userID, email, sid string
			var org string
			var emailVerified bool
			var roles, orgRoles, ents []string

			if v, _ := claims["sub"].(string); v != "" {
				userID = v
			}
			if v, _ := claims["email"].(string); v != "" {
				email = v
			}
			if v, _ := claims["email_verified"].(bool); v {
				emailVerified = v
			}
			username, _ := claims["username"].(string)
			discord, _ := claims["discord_username"].(string)
			if v, _ := claims["sid"].(string); v != "" {
				sid = v
			}
			if v, _ := claims["org"].(string); v != "" {
				org = v
			}

			if rs, ok := claims["roles"].([]any); ok {
				for _, v := range rs {
					if s, ok := v.(string); ok {
						roles = append(roles, s)
					}
				}
			} else if rs, ok := claims["roles"].([]string); ok {
				roles = append(roles, rs...)
			}
			if rs, ok := claims["org_roles"].([]any); ok {
				for _, v := range rs {
					if s, ok := v.(string); ok {
						orgRoles = append(orgRoles, s)
					}
				}
			} else if rs, ok := claims["org_roles"].([]string); ok {
				orgRoles = append(orgRoles, rs...)
			}
			if es, ok := claims["entitlements"].([]any); ok {
				for _, v := range es {
					if s, ok := v.(string); ok {
						ents = append(ents, s)
					}
				}
			} else if es, ok := claims["entitlements"].([]string); ok {
				ents = append(ents, es...)
			}

			// Best-effort DB enrichment for discord username.
			if userID != "" {
				if du, err := svc.GetProviderUsername(r.Context(), userID, "discord"); err == nil && du != "" {
					discord = du
				}
			}

			// Best-effort enrichment for verify-only mode (when a service is attached).
			if userID != "" {
				// Roles are only meaningful in org_mode=single.
				if strings.EqualFold(strings.TrimSpace(svc.Options().OrgMode), "single") {
					// Roles: if token has no roles, allow the verifier to supply canonical roles.
					if len(roles) == 0 {
						if rs := svc.ListRoleSlugsByUser(r.Context(), userID); len(rs) > 0 {
							roles = rs
						}
					}
				}
				// Email: if token has no email claim, allow an attached service to supply canonical email.
				type emailLookup interface {
					GetEmailByUserID(ctx context.Context, id string) (string, error)
				}
				if email == "" {
					if el, ok := svc.(emailLookup); ok {
						if e, err := el.GetEmailByUserID(r.Context(), userID); err == nil && strings.TrimSpace(e) != "" {
							email = e
						}
					}
				}
			}

			// Optional live user gate (ban/deleted) when the verifier is service-backed.
			if userID != "" {
				type userGate interface {
					IsUserAllowed(ctx context.Context, userID string) (bool, error)
				}
				if ug, ok := svc.(userGate); ok {
					allowed, err := ug.IsUserAllowed(r.Context(), userID)
					if err != nil || !allowed {
						unauthorized(w, "user_disabled")
						return
					}
				}
			}

			cl := Claims{
				UserID:          userID,
				Email:           email,
				EmailVerified:   emailVerified,
				Username:        username,
				DiscordUsername: discord,
				SessionID:       sid,
				Roles:           roles,
				Org:             org,
				OrgRoles:        orgRoles,
				Entitlements:    ents,
			}
			r = r.WithContext(setClaims(r.Context(), cl))
			next.ServeHTTP(w, r)
		})
	}
}

// Optional validates when Authorization is present; otherwise passes through.
func Optional(svc core.Verifier) func(http.Handler) http.Handler {
	req := Required(svc)
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

func audContains(aud any, want string) bool {
	switch v := aud.(type) {
	case string:
		return v == want
	case []any:
		for _, e := range v {
			if s, ok := e.(string); ok && s == want {
				return true
			}
		}
	case []string:
		for _, e := range v {
			if e == want {
				return true
			}
		}
	}
	return false
}

func audContainsAny(aud any, want []string) bool {
	for _, w := range want {
		if audContains(aud, w) {
			return true
		}
	}
	return false
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
