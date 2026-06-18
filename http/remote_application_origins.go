package authhttp

import (
	"context"
	"errors"
	"net/http"
	"strconv"
	"strings"
	"time"

	core "github.com/open-rails/authkit/core"
)

var errNoRemoteApplicationSource = errors.New("no remote_application source available")

// RemoteApplicationAllowedOrigins returns the de-duplicated union of enabled
// remote_application browser origins. This is useful for CORS preflight, which
// carries an Origin but no JWT issuer.
func (v *Verifier) RemoteApplicationAllowedOrigins(ctx context.Context) ([]string, error) {
	src := v.remoteApplicationSource()
	if src == nil {
		return nil, errNoRemoteApplicationSource
	}
	apps, err := src.ListRemoteApplications(ctx, true)
	if err != nil {
		return nil, err
	}
	seen := map[string]struct{}{}
	var out []string
	for _, app := range apps {
		for _, raw := range app.AllowedOrigins {
			origin, err := core.NormalizeAllowedOrigin(raw)
			if err != nil {
				continue
			}
			if _, ok := seen[origin]; ok {
				continue
			}
			seen[origin] = struct{}{}
			out = append(out, origin)
		}
	}
	return out, nil
}

// OriginAllowedForIssuer checks a real request Origin against the
// remote_application registered for the already-verified JWT issuer.
func (v *Verifier) OriginAllowedForIssuer(ctx context.Context, issuer, origin string, allowNoOrigin bool) (bool, error) {
	origin = strings.TrimSpace(origin)
	if origin == "" {
		return allowNoOrigin, nil
	}
	src := v.remoteApplicationSource()
	if src == nil {
		return false, errNoRemoteApplicationSource
	}
	app, err := src.GetRemoteApplication(ctx, strings.TrimSpace(issuer))
	if err != nil || app == nil || !app.Enabled {
		return false, err
	}
	return core.OriginAllowed(origin, app.AllowedOrigins), nil
}

func (v *Verifier) remoteApplicationSource() RemoteApplicationSource {
	if v == nil {
		return nil
	}
	v.mu.Lock()
	defer v.mu.Unlock()
	if v.fedSource != nil {
		return v.fedSource
	}
	if v.enrich != nil {
		return v.enrich
	}
	return nil
}

// RemoteApplicationCORS handles browser preflight using the union of enabled
// remote_application allowed origins. It is compatibility/browser hardening, not
// authorization; use RequireDelegatedOrigin after Required for the real
// issuer-vs-Origin check.
func RemoteApplicationCORS(v *Verifier) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			origin := strings.TrimSpace(r.Header.Get("Origin"))
			if origin == "" {
				next.ServeHTTP(w, r)
				return
			}
			origins, err := v.RemoteApplicationAllowedOrigins(r.Context())
			allowed := err == nil && core.OriginAllowed(origin, origins)
			if !allowed {
				if r.Method == http.MethodOptions {
					forbidden(w, "origin_not_allowed")
					return
				}
				next.ServeHTTP(w, r)
				return
			}
			addVary(w.Header(), "Origin")
			w.Header().Set("Access-Control-Allow-Origin", origin)
			w.Header().Set("Access-Control-Allow-Credentials", "true")
			if r.Method == http.MethodOptions {
				w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, PATCH, DELETE, OPTIONS")
				w.Header().Set("Access-Control-Allow-Headers", "Authorization, Content-Type, Accept")
				w.Header().Set("Access-Control-Max-Age", strconv.Itoa(int((12*time.Hour)/time.Second)))
				w.WriteHeader(http.StatusNoContent)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

// RequireDelegatedOrigin enforces Origin against the verified issuer for
// delegated JWT requests. Mount it after Required. Non-delegated requests pass
// through unchanged.
func RequireDelegatedOrigin(v *Verifier, allowNoOrigin bool) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			claims, ok := ClaimsFromContext(r.Context())
			if !ok {
				unauthorized(w, "missing_claims")
				return
			}
			if !claims.IsDelegated() {
				next.ServeHTTP(w, r)
				return
			}
			allowed, err := v.OriginAllowedForIssuer(r.Context(), claims.Issuer, r.Header.Get("Origin"), allowNoOrigin)
			if err != nil || !allowed {
				forbidden(w, "origin_not_allowed")
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

func addVary(h http.Header, value string) {
	for _, part := range strings.Split(h.Get("Vary"), ",") {
		if strings.EqualFold(strings.TrimSpace(part), value) {
			return
		}
	}
	h.Add("Vary", value)
}
