package authgin

import (
	"net/http"
	"strings"

	"github.com/PaulFidika/authkit/adapters/ginutil"
	core "github.com/PaulFidika/authkit/core"
	"github.com/gin-gonic/gin"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Auth provides a unified middleware surface whether you mount full AuthKit routes (Service)
// or use the JWKS Verifier only. It exposes Required/Optional and DB-backed Role/Entitlement gates.
type Auth struct {
	svc core.Verifier
	ver *Verifier
}

// MiddlewareFromConfig constructs a verify-only Auth wrapper from an AcceptConfig.
func MiddlewareFromConfig(accept core.AcceptConfig) *Auth { return &Auth{ver: NewVerifier(accept)} }

// MiddlewareFromSVC constructs an Auth gate from an AuthKit Service.
func MiddlewareFromSVC(s *Service) *Auth { return &Auth{svc: s.Core()} }

// Admin/RequireAdmin live here on Auth for discoverability.

// Required validates the token and attaches claims/user_id/email. When using Verifier,
// it also enriches claims from DB if the Verifier has WithService(svc).
func (a *Auth) Required() gin.HandlerFunc {
	if a.ver != nil {
		// Short-circuit: if claims already present (from Optional/OptionalWithContext on group), skip re-verify
		required := a.ver.MiddlewareRequired()
		return func(c *gin.Context) {
			if _, ok := c.Get("authkit.claims"); ok || c.GetString("auth.user_id") != "" {
				c.Next()
				return
			}
			required(c)
		}
	}
	// Service-backed path
	required := AuthRequired(a.svc)
	return func(c *gin.Context) {
		if _, ok := c.Get("authkit.claims"); ok || c.GetString("auth.user_id") != "" {
			c.Next()
			return
		}
		required(c)
	}
}

// Optional validates when Authorization is present; otherwise passes through.
func (a *Auth) Optional() gin.HandlerFunc {
	if a.ver != nil {
		return a.ver.MiddlewareOptional()
	}
	return AuthOptional(a.svc)
}

// RequireRole checks DB roles for the given slug (never trusts JWT roles).
func (a *Auth) RequireRole(role string) gin.HandlerFunc {
	req := a.Required()
	return func(c *gin.Context) {
		req(c)
		if c.IsAborted() {
			return
		}
		rolesAny, ok := c.Get("auth.roles")
		if !ok {
			ginutil.Forbidden(c, "forbidden")
			return
		}
		roles, _ := rolesAny.([]string)
		for _, r := range roles {
			if strings.EqualFold(r, role) {
				c.Next()
				return
			}
		}
		ginutil.Forbidden(c, "forbidden")
	}
}

// RequireEntitlement checks entitlements for the given slug using the Service.
func (a *Auth) RequireEntitlement(ent string) gin.HandlerFunc {
	req := a.Required()
	return func(c *gin.Context) {
		req(c)
		if c.IsAborted() {
			return
		}
		entsAny, ok := c.Get("auth.entitlements")
		if !ok {
			c.AbortWithStatusJSON(http.StatusPaymentRequired, gin.H{"error": "entitlement_required", "entitlement": ent})
			return
		}
		ents, _ := entsAny.([]string)
		for _, e := range ents {
			if strings.EqualFold(e, ent) {
				c.Next()
				return
			}
		}
		c.AbortWithStatusJSON(http.StatusPaymentRequired, gin.H{"error": "entitlement_required", "entitlement": ent})
	}
}

// RequireAdmin verifies JWT then checks admin role directly in Postgres.
// Use when you want a strict, DB-backed admin gate without attaching full user context.
func (a *Auth) RequireAdmin(pg *pgxpool.Pool) gin.HandlerFunc {
	//	req := a.Required()
	return func(c *gin.Context) {

		uid := c.GetString("auth.user_id")
		if uid == "" || pg == nil {
			ginutil.Forbidden(c, "forbidden")
			return
		}
		var isAdmin bool
		err := pg.QueryRow(c.Request.Context(), `
            SELECT EXISTS (
              SELECT 1 FROM profiles.user_roles ur
              JOIN profiles.roles r ON ur.role_id = r.id
              WHERE ur.user_id = $1 AND r.slug = 'admin'
                AND r.deleted_at IS NULL
            )
        `, uid).Scan(&isAdmin)

		if err == nil && isAdmin {
			c.Next()
			return
		}

		ginutil.Forbidden(c, "forbidden")
		//req(c)
		//if c.IsAborted() {
		//	return
		//}
	}
}

// Admin is an alias for RequireAdmin.
func (a *Auth) Admin(pg *pgxpool.Pool) gin.HandlerFunc { return a.RequireAdmin(pg) }
