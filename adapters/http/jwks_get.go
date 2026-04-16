package authhttp

import (
	"net/http"

	jwtkit "github.com/open-rails/authkit/jwt"
)

// JWKSHandler serves the public JWKS document for the given key set.
func JWKSHandler(jwks jwtkit.JWKS) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		jwtkit.ServeJWKS(w, r, jwks)
	})
}
