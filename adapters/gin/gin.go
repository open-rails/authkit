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

// Required is the gin-native form of verify.Required (#209): validates the
// Bearer token and stores claims in the request context, aborting with the
// verifier's 401 on failure. src is the *authkit.Client (or a
// *verify.Verifier):
//
//	api := r.Group("/api", authkitgin.Required(auth))
func Required(src verify.VerifierSource) gin.HandlerFunc {
	return Use(verify.Required(verifierOf(src)))
}

// Optional is the gin-native form of verify.Optional (#209): passes through
// anonymously when Authorization is absent and otherwise validates it. A
// present invalid credential is rejected. See Required for usage.
func Optional(src verify.VerifierSource) gin.HandlerFunc {
	return Use(verify.Optional(verifierOf(src)))
}

// RequiredLive is the gin-native form of verify.RequiredLive (#267): Required
// plus a per-request account-liveness gate, so a banned or deleted user is
// rejected on their next request and the handler reads fresh identity claims.
// Returns verify.ErrLivenessUnconfigured when the verifier has no
// LivenessSource wired.
func RequiredLive(src verify.VerifierSource) (gin.HandlerFunc, error) {
	mw, err := verify.RequiredLive(verifierOf(src))
	if err != nil {
		return nil, err
	}
	return Use(mw), nil
}

// OptionalLive admits anonymous requests and checks the liveness of presented
// native-user credentials. It returns verify.ErrLivenessUnconfigured at startup
// when no source is wired. Use on routes, groups, or as application middleware.
func OptionalLive(src verify.VerifierSource) (gin.HandlerFunc, error) {
	mw, err := verify.OptionalLive(verifierOf(src))
	if err != nil {
		return nil, err
	}
	return Use(mw), nil
}

func verifierOf(src verify.VerifierSource) *verify.Verifier {
	if src == nil {
		return nil
	}
	return src.Verifier()
}

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

// RequirePermission authenticates the request (it includes Required) and
// requires perm, checked live, in the group SetGroup attached. A request with
// no group fails closed (500). It panics at construction on a perm the
// authority does not register.
func RequirePermission(a verify.Authority, perm iam.Perm) gin.HandlerFunc {
	return Use(verify.RequirePermission(a, perm))
}

// RequirePermissionOn is RequirePermission in one fixed group, such as
// iam.RootGroup().
func RequirePermissionOn(a verify.Authority, ref iam.GroupRef, perm iam.Perm) gin.HandlerFunc {
	return Use(verify.RequirePermissionOn(a, ref, perm))
}
