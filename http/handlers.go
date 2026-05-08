package authhttp

import (
	"net/http"

	core "github.com/open-rails/authkit/core"
)

// JWKSHandler returns a handler for GET /.well-known/jwks.json.
func (s *Service) JWKSHandler() http.Handler {
	return JWKSHandler(s.svc.JWKS())
}

// APIHandler returns a handler that serves prefix-neutral JSON API routes.
// It is intended to be mounted under the host's mux/router at the host's chosen API prefix.
func (s *Service) APIHandler() http.Handler {
	if s == nil || s.svc == nil || s.verifier == nil {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { serverErr(w, "authkit_not_initialized") })
	}
	if err := s.svc.ValidateVerificationConfiguration(); err != nil {
		panic(err)
	}
	if !core.IsDevEnvironment(s.svc.Options().Environment) {
		if s.svc.EphemeralMode() != core.EphemeralRedis {
			panic("authkit: redis-compatible ephemeral store is required in production")
		}
	}

	mux := http.NewServeMux()
	for _, route := range s.APIRoutes() {
		mux.Handle(route.Method+" "+route.Path, route.Handler)
	}
	return mux
}
