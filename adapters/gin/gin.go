// Package authkitgin bridges AuthKit's net/http middleware to Gin. Mount
// registers AuthKit's routes directly on the engine; verification policy
// stays in verify.
package authkitgin

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/open-rails/authkit/iam"
	"github.com/open-rails/authkit/verify"
	"github.com/open-rails/helpers/auth"
)

// Required is the gin-native form of verify.Required (#209): validates the
// Bearer token and stores claims in the request context, aborting with the
// verifier's 401 on failure. Use it directly on gin routes/groups instead of
// hand-writing an http.Handler↔gin.HandlerFunc shim:
//
//	api := r.Group("/api", authkitgin.Required(verifier))
func Required(v *verify.Verifier) gin.HandlerFunc { return Use(verify.Required(v)) }

// Optional is the gin-native form of verify.Optional (#209): passes through
// anonymously when Authorization is absent and otherwise validates it. A
// present invalid credential is rejected. See Required for usage.
func Optional(v *verify.Verifier) gin.HandlerFunc { return Use(verify.Optional(v)) }

// RequiredLive is the gin-native form of verify.RequiredLive (#267): Required
// plus a per-request account-liveness gate, so a banned or deleted user is
// rejected on their next request and the handler reads fresh identity claims.
// Returns verify.ErrLivenessUnconfigured when the verifier has no
// LivenessSource wired.
func RequiredLive(v *verify.Verifier) (gin.HandlerFunc, error) {
	mw, err := verify.RequiredLive(v)
	if err != nil {
		return nil, err
	}
	return Use(mw), nil
}

// OptionalLive admits anonymous requests and checks the liveness of presented
// native-user credentials. It returns verify.ErrLivenessUnconfigured at startup
// when no source is wired. Use on routes, groups, or as application middleware.
func OptionalLive(v *verify.Verifier) (gin.HandlerFunc, error) {
	mw, err := verify.OptionalLive(v)
	if err != nil {
		return nil, err
	}
	return Use(mw), nil
}

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

// Identity returns the verified caller's provider-neutral identity (user,
// device key, API key, remote application or delegated principal).
func Identity(c *gin.Context) (auth.Identity, bool) {
	if c == nil || c.Request == nil {
		return auth.Identity{}, false
	}
	cl, ok := verify.ClaimsFromContext(c.Request.Context())
	if !ok {
		return auth.Identity{}, false
	}
	return cl.Identity()
}

// Actor returns the actor the verified caller acts as, for passing to *authkit.Auth
// operations. ok is false when the caller carries no AuthKit authority.
func Actor(c *gin.Context) (iam.Actor, bool) {
	if c == nil || c.Request == nil {
		return iam.Actor{}, false
	}
	return verify.ActorFromContext(c.Request.Context())
}

// UserClaims reads a verified local user without performing a database lookup.
// Profile availability depends on Required/Optional versus RequiredLive.
func UserClaims(c *gin.Context) (verify.UserClaimsData, bool) {
	if c == nil || c.Request == nil {
		return verify.UserClaimsData{}, false
	}
	return verify.UserClaimsFromContext(c.Request.Context())
}

// RequirePermission authenticates the request (it includes Required) and
// requires perm, checked live, in the group resolve returns; a nil resolve
// means the root group. It panics at construction on a perm the authority
// does not register.
func RequirePermission(a verify.Authority, perm iam.Perm, resolve func(*gin.Context) iam.GroupRef) gin.HandlerFunc {
	verify.MustKnowPermission(a, perm)
	return func(c *gin.Context) {
		var r func(*http.Request) iam.GroupRef
		if resolve != nil {
			r = func(*http.Request) iam.GroupRef { return resolve(c) }
		}
		Use(verify.RequirePermission(a, perm, r))(c)
	}
}
