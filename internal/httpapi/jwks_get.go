package httpapi

import (
	"net/http"

	"github.com/open-rails/authkit/internal/jose"
)

// JWKSHandler returns a handler for GET /.well-known/jwks.json. The key set is
// read per request so a hot-reloaded rotation or key removal is published
// immediately (ak#392).
func (s *Service) JWKSHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		jose.ServeJWKS(w, r, s.svc.JWKS())
	})
}
