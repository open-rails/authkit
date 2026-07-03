package authhttp

import (
	"net/http"
	"strings"

	"github.com/open-rails/authkit/oidckit"
)

// OIDCHandler returns a handler that serves browser redirect flows:
// - GET /oidc/{provider}/login
// - GET /oidc/{provider}/callback
// - GET /oidc/{provider}/step-up/callback
func (s *Service) OIDCHandler() http.Handler {
	if s == nil || s.svc == nil {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { serverErr(w, ErrAuthkitNotInitialized) })
	}

	mux := http.NewServeMux()
	for _, route := range s.OIDCBrowserRoutes() {
		mux.Handle(route.Method+" "+joinRoutePath("/oidc", route.Path), route.Handler)
	}
	return mux
}

type oidcConfig struct {
	Manager    *oidckit.Manager
	StateCache oidckit.StateCache
}

func (s *Service) oidcCfg() oidcConfig {
	return oidcConfig{
		Manager:    s.oidcManager(),
		StateCache: s.stateCache(),
	}
}

func joinRoutePath(prefix, path string) string {
	prefix = "/" + strings.Trim(strings.TrimSpace(prefix), "/")
	if prefix == "/" {
		prefix = ""
	}
	path = "/" + strings.Trim(strings.TrimSpace(path), "/")
	if path == "/" {
		path = ""
	}
	if prefix == "" && path == "" {
		return "/"
	}
	return prefix + path
}
