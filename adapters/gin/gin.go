// Package authkitgin bridges AuthKit's net/http middleware to Gin. Mount
// registers AuthKit's routes directly on the engine; verification policy
// stays in verify. Handlers read the verified caller from
// c.Request.Context() (verify.ActorFromContext, verify.ClaimsFromContext) and
// write AuthKit errors with c.JSON(iam.ErrorResponse(err)).
package authkitgin

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/open-rails/authkit/iam"
	"github.com/open-rails/authkit/verify"
)

// Required is verify.Required in a gin chain: a is the *authkit.Client (or a
// *verify.Verifier).
//
//	api := r.Group("/api", authkitgin.Required(auth))
func Required(a verify.Authenticator) gin.HandlerFunc { return Use(verify.Required(a)) }

// Optional is verify.Optional in a gin chain.
func Optional(a verify.Authenticator) gin.HandlerFunc { return Use(verify.Optional(a)) }

// Use runs net/http middleware in a gin chain; a middleware that does not call
// its next handler aborts the chain.
func Use(mw ...func(http.Handler) http.Handler) gin.HandlerFunc {
	return func(c *gin.Context) {
		terminalRan := false
		var h http.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			terminalRan = true
			c.Request = r
			c.Next()
		})
		for i := len(mw) - 1; i >= 0; i-- {
			if mw[i] != nil {
				h = mw[i](h)
			}
		}
		h.ServeHTTP(c.Writer, c.Request)
		if !terminalRan {
			c.Abort()
		}
	}
}

// SetGroup attaches the permission group the request acts in, for
// RequirePermission: call it from the loader that resolves the route's entity.
func SetGroup(c *gin.Context, ref iam.GroupRef) {
	c.Request = c.Request.WithContext(verify.WithGroup(c.Request.Context(), ref))
}

// RequireSession is verify.RequireSession in a gin chain.
func RequireSession(a verify.Authority) gin.HandlerFunc { return Use(verify.RequireSession(a)) }

// RequirePermission is verify.RequirePermission in a gin chain, in the group
// SetGroup attached.
func RequirePermission(a verify.Authority, perm iam.Perm) gin.HandlerFunc {
	return Use(verify.RequirePermission(a, perm))
}

// RequirePermissionOn is verify.RequirePermissionOn in a gin chain.
func RequirePermissionOn(a verify.Authority, ref iam.GroupRef, perm iam.Perm) gin.HandlerFunc {
	return Use(verify.RequirePermissionOn(a, ref, perm))
}

// Sensitive is verify.Sensitive in a gin chain.
func Sensitive(a verify.Authority) gin.HandlerFunc { return Use(verify.Sensitive(a)) }
