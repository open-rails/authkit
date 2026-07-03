package authkitgin

import (
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	authkit "github.com/open-rails/authkit"
	"github.com/open-rails/authkit/adapters/internal/routepath"
	"github.com/open-rails/authkit/authhttp"
	"github.com/open-rails/authkit/verify"
)

type APIOptions struct {
	Routes    []authhttp.RouteSpec
	Groups    []authhttp.RouteGroup
	Wrap      func(authhttp.RouteSpec, http.Handler) http.Handler
	routesSet bool
}

type APIOption func(*APIOptions)

func WithRoutes(routes []authhttp.RouteSpec) APIOption {
	return func(opts *APIOptions) {
		opts.Routes = routes
		opts.routesSet = true
	}
}

func WithGroups(groups ...authhttp.RouteGroup) APIOption {
	return func(opts *APIOptions) {
		opts.Groups = append([]authhttp.RouteGroup(nil), groups...)
	}
}

func WithRouteWrapper(wrap func(authhttp.RouteSpec, http.Handler) http.Handler) APIOption {
	return func(opts *APIOptions) {
		opts.Wrap = wrap
	}
}

func RegisterAPI(r gin.IRouter, svc *authhttp.Service, options ...APIOption) {
	if r == nil || svc == nil {
		return
	}
	opts := APIOptions{}
	for _, option := range options {
		if option != nil {
			option(&opts)
		}
	}
	if !opts.routesSet {
		if opts.Groups != nil {
			opts.Routes = svc.Routes().Groups(opts.Groups...)
		} else {
			opts.Routes = svc.Routes().DefaultAPI()
		}
	}
	registerRoutes(r, opts.Routes, opts.Wrap)
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

func RegisterRoutes(r gin.IRouter, routes []authhttp.RouteSpec, wrap func(authhttp.RouteSpec, http.Handler) http.Handler) {
	if r == nil {
		return
	}
	registerRoutes(r, routes, wrap)
}

func RegisterOIDC(r gin.IRouter, svc *authhttp.Service, mountPath string) {
	if r == nil || svc == nil {
		return
	}
	prefix := routepath.Clean(mountPath)
	routes := svc.Routes().OIDCBrowser()
	for i := range routes {
		routes[i].Path = routepath.Join(prefix, routes[i].Path)
	}
	registerRoutes(r, routes, nil)
}

func RegisterJWKS(r gin.IRouter, svc *authhttp.Service) {
	if r == nil || svc == nil {
		return
	}
	r.GET("/.well-known/jwks.json", gin.WrapH(svc.JWKSHandler()))
}

func registerRoutes(r gin.IRouter, routes []authhttp.RouteSpec, wrap func(authhttp.RouteSpec, http.Handler) http.Handler) {
	for _, route := range routes {
		if route.Method == "" || route.Path == "" || route.Handler == nil {
			continue
		}
		handler := route.Handler
		if wrap != nil {
			handler = wrap(route, handler)
		}
		paramNames := routepath.ParamNames(route.Path)
		r.Handle(route.Method, ginPath(route.Path), func(c *gin.Context) {
			for _, name := range paramNames {
				c.Request.SetPathValue(name, c.Param(name))
			}
			handler.ServeHTTP(c.Writer, c.Request)
		})
	}
}

func ginPath(path string) string {
	parts := strings.Split(path, "/")
	for i, part := range parts {
		if strings.HasPrefix(part, "{") && strings.HasSuffix(part, "}") {
			name := strings.TrimSuffix(strings.TrimPrefix(part, "{"), "}")
			parts[i] = ":" + name
		}
	}
	return strings.Join(parts, "/")
}
