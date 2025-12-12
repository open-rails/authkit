package handlers

import (
	core "github.com/PaulFidika/authkit/core"
	jwtkit "github.com/PaulFidika/authkit/jwt"
	"github.com/gin-gonic/gin"
)

// HandleJWKS serves the public JWKS document.
func HandleJWKS(svc core.Verifier) gin.HandlerFunc {
	return func(c *gin.Context) {
		jwks := svc.JWKS()
		jwtkit.ServeJWKS(c.Writer, c.Request, jwks)
	}
}
