package authhttp

import (
	"net/http"

	"github.com/open-rails/authkit/jwtkit"
)

// JWKSHandler returns a handler for GET /.well-known/jwks.json.
func (s *Service) JWKSHandler() http.Handler { return JWKSHandler(s.svc.JWKS()) }

// JWKSHandler serves the public JWKS document for the given key set.
func JWKSHandler(jwks jwtkit.JWKS) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		jwtkit.ServeJWKS(w, r, jwks)
	})
}
