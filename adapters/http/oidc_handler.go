package authhttp

import (
	"net/http"

	oidckit "github.com/PaulFidika/authkit/oidc"
)

// OIDCHandler returns a handler that serves browser redirect flows:
// - GET /auth/oidc/{provider}/login
// - GET /auth/oidc/{provider}/callback
// - GET /auth/oauth/discord/login (if configured)
// - GET /auth/oauth/discord/callback (if configured)
func (s *Service) OIDCHandler() http.Handler {
	if s == nil || s.svc == nil {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { serverErr(w, "authkit_not_initialized") })
	}

	mux := http.NewServeMux()
	mux.Handle("GET /auth/oidc/{provider}/login", http.HandlerFunc(s.handleOIDCLoginGET))
	mux.Handle("GET /auth/oidc/{provider}/callback", http.HandlerFunc(s.handleOIDCCallbackGET))
	if _, ok := s.oidcProviders["discord"]; ok {
		mux.Handle("GET /auth/oauth/discord/login", http.HandlerFunc(s.handleDiscordLoginGET))
		mux.Handle("GET /auth/oauth/discord/callback", http.HandlerFunc(s.handleDiscordCallbackGET))
	}

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
