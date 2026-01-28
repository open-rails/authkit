package authhttp

import (
	"net/http"

	core "github.com/PaulFidika/authkit/core"
	jwtkit "github.com/PaulFidika/authkit/jwt"
)

// JWKSHandler serves the public JWKS document.
func JWKSHandler(svc core.Verifier) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		jwtkit.ServeJWKS(w, r, svc.JWKS())
	})
}
