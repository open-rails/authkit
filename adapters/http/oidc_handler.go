package authhttp

import (
	"net/http"

	oidckit "github.com/open-rails/authkit/oidc"
)

// OIDCHandler returns a handler that serves browser redirect flows:
// - GET /oidc/{provider}/login
// - GET /oidc/{provider}/callback
func (s *Service) OIDCHandler() http.Handler {
	if s == nil || s.svc == nil {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { serverErr(w, "authkit_not_initialized") })
	}

	mux := http.NewServeMux()
	mux.Handle("GET /oidc/{provider}/login", http.HandlerFunc(s.handleOIDCLoginGET))
	mux.Handle("GET /oidc/{provider}/callback", http.HandlerFunc(s.handleOIDCCallbackGET))

	h := http.Handler(mux)
	h = LanguageMiddleware(s.langCfg)(h)
	return h
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
