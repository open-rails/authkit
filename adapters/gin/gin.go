// Package authkitgin bridges AuthKit's net/http middleware to gin. Route
// mounting is NOT here (#250): build the whole surface with
// authhttp.MountHandler and mount it once via gin.WrapH.
package authkitgin

import (
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	authkit "github.com/open-rails/authkit"
	"github.com/open-rails/authkit/verify"
)

// Fallback adapts a neutral handler (authhttp.MountHandler) for use as a gin
// NoRoute fallback. gin pre-sets 404 on the response before running NoRoute
// handlers, which silently overrides any handler that relies on the implicit
// 200-on-first-write; this clears the pending status so the mounted handler's
// own status wins (its 404s still 404).
//
//	router.NoRoute(authkitgin.Fallback(mount))
//
// For explicit wildcard mounts (r.Any("/oidc/*path", …)) plain gin.WrapH is
// fine — gin only pre-sets 404 on the NoRoute path.
func Fallback(h http.Handler) gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Writer.WriteHeader(http.StatusOK)
		h.ServeHTTP(c.Writer, c.Request)
	}
}

// Required is the gin-native form of verify.Required (#209): validates the
// Bearer token and stores claims in the request context, aborting with the
// verifier's 401 on failure. Use it directly on gin routes/groups instead of
// hand-writing an http.Handler↔gin.HandlerFunc shim:
//
//	api := r.Group("/api", authkitgin.Required(verifier))
func Required(v *verify.Verifier) gin.HandlerFunc { return Use(verify.Required(v)) }

// Optional is the gin-native form of verify.Optional (#209): parses and stores
// claims when a valid Bearer token is present, and passes through anonymously
// otherwise. See Required for usage.
func Optional(v *verify.Verifier) gin.HandlerFunc { return Use(verify.Optional(v)) }

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

func Principal(c *gin.Context) (authkit.Principal, bool) {
	if c == nil || c.Request == nil {
		return authkit.Principal{}, false
	}
	cl, ok := verify.ClaimsFromContext(c.Request.Context())
	if !ok {
		return authkit.Principal{}, false
	}
	p := cl.Principal()
	return p, p.Kind != ""
}

type UserClaimsData struct {
	UserID        string
	Email         string
	EmailVerified bool
	Username      string
	SessionID     string
	Entitlements  []string
	AMR           []string
	ACR           string
	AuthTime      time.Time
	MFAEnrolled   bool
}

func UserClaims(c *gin.Context) (UserClaimsData, bool) {
	if c == nil || c.Request == nil {
		return UserClaimsData{}, false
	}
	cl, ok := verify.ClaimsFromContext(c.Request.Context())
	if !ok || !cl.IsUser() {
		return UserClaimsData{}, false
	}
	return UserClaimsData{
		UserID:        cl.UserID,
		Email:         cl.Email,
		EmailVerified: cl.EmailVerified,
		Username:      cl.Username,
		SessionID:     cl.SessionID,
		Entitlements:  append([]string(nil), cl.Entitlements...),
		AMR:           append([]string(nil), cl.AMR...),
		ACR:           cl.ACR,
		AuthTime:      cl.AuthTime,
		MFAEnrolled:   cl.MFAEnrolled,
	}, true
}

func RequirePermission(checker verify.PermissionChecker, perm string, resolve func(*gin.Context) verify.PermissionScope) gin.HandlerFunc {
	return func(c *gin.Context) {
		var mw func(http.Handler) http.Handler
		if resolve == nil {
			mw = verify.RequirePermission(checker, perm, nil)
		} else {
			mw = verify.RequirePermission(checker, perm, func(*http.Request) verify.PermissionScope {
				return resolve(c)
			})
		}
		Use(mw)(c)
	}
}
