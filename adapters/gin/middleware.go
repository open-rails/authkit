package authgin

import (
	"context"
	"net/http"
	"strings"
	"time"

	"github.com/PaulFidika/authkit/adapters/ginutil"
	core "github.com/PaulFidika/authkit/core"
	"github.com/gin-gonic/gin"
	jwt "github.com/golang-jwt/jwt/v5"
)

// AuthRequired validates the Bearer ID token (JWT), enforces iss/aud/exp, and stores user info in context.
func AuthRequired(svc core.Verifier) gin.HandlerFunc {
	return func(c *gin.Context) {
		tokenStr := ginutil.BearerToken(c.GetHeader("Authorization"))
		if tokenStr == "" {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "missing_token"})
			return
		}
		claims := jwt.MapClaims{}
		token, err := jwt.ParseWithClaims(tokenStr, claims, svc.Keyfunc())
		if err != nil || !token.Valid {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "invalid_token"})
			return
		}
		// Basic claim checks
		opts := svc.Options()
		if iss, _ := claims["iss"].(string); iss != opts.Issuer {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "bad_issuer"})
			return
		}
		switch {
		case len(opts.ExpectedAudiences) > 0:
			if !audContainsAny(claims["aud"], opts.ExpectedAudiences) {
				c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "bad_audience"})
				return
			}
		case opts.ExpectedAudience != "":
			if !audContains(claims["aud"], opts.ExpectedAudience) {
				c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "bad_audience"})
				return
			}
		}
		if expUnix, ok := toUnix(claims["exp"]); ok {
			if time.Unix(expUnix, 0).Before(time.Now().Add(-time.Second)) {
				c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "token_expired"})
				return
			}
		}
		// Attach common fields
		// Extract typed claims and attach in both Gin context and request context
		var userID, email string
		var emailVerified bool
		var sid string
		var roles, ents []string
		if v, _ := claims["sub"].(string); v != "" {
			userID = v
			c.Set("auth.user_id", v)
		}
		if v, _ := claims["email"].(string); v != "" {
			email = v
			c.Set("auth.email", v)
		}
		if v, _ := claims["email_verified"].(bool); v {
			emailVerified = v
			c.Set("auth.email_verified", v)
		}
		if v, _ := claims["username"].(string); v != "" {
			c.Set("auth.username", v)
		}
		if v, _ := claims["discord_username"].(string); v != "" {
			c.Set("auth.discord_username", v)
		}
		if v, _ := claims["sid"].(string); v != "" {
			sid = v
			c.Set("auth.sid", v)
		}
		if rs, ok := claims["roles"].([]any); ok {
			for _, v := range rs {
				if s, ok := v.(string); ok {
					roles = append(roles, s)
				}
			}
		} else if rs, ok := claims["roles"].([]string); ok {
			roles = append(roles, rs...)
		}
		if len(roles) > 0 {
			c.Set("auth.roles", roles)
		}
		if es, ok := claims["entitlements"].([]any); ok {
			for _, v := range es {
				if s, ok := v.(string); ok {
					ents = append(ents, s)
				}
			}
		} else if es, ok := claims["entitlements"].([]string); ok {
			ents = append(ents, es...)
		}
		if len(ents) > 0 {
			c.Set("auth.entitlements", ents)
		}
		// Fetch Discord username from DB to mirror email availability (best-effort)
		if userID != "" {
			if du, err := svc.GetProviderUsername(c.Request.Context(), userID, "discord"); err == nil && du != "" {
				c.Set("auth.discord_username", du)
			}
		}

		// Optional live user gate (ban/deleted) when the verifier is service-backed.
		if userID != "" {
			type userGate interface {
				IsUserAllowed(ctx context.Context, userID string) (bool, error)
			}
			if ug, ok := svc.(userGate); ok {
				allowed, err := ug.IsUserAllowed(c.Request.Context(), userID)
				if err != nil || !allowed {
					c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "user_disabled"})
					return
				}
			}
		}

		// Build typed claims, prefer optional username/discord values if present
		uname, _ := c.Get("auth.username")
		duVal, _ := c.Get("auth.discord_username")
		cl := Claims{UserID: userID, Email: email, EmailVerified: emailVerified, SessionID: sid, Roles: roles, Entitlements: ents}
		if us, ok := uname.(string); ok {
			cl.Username = us
		}
		if ds, ok := duVal.(string); ok {
			cl.DiscordUsername = ds
		}
		c.Set("authkit.claims", cl)
		c.Request = c.Request.WithContext(SetClaims(c.Request.Context(), cl))
		c.Next()
	}
}

// AuthOptional passes through when no token is present; validates if present.
func AuthOptional(svc core.Verifier) gin.HandlerFunc {
	required := AuthRequired(svc)
	return func(c *gin.Context) {
		if ginutil.BearerToken(c.GetHeader("Authorization")) == "" {
			c.Next()
			return
		}
		required(c)
	}
}

// RoleRequired checks JWT roles claim for the given slug.
func RoleRequired(svc core.Verifier, role string) gin.HandlerFunc {
	required := AuthRequired(svc)

	return func(c *gin.Context) {
		required(c)
		if c.IsAborted() {
			return
		}

		// Always prefer a fresh DB check for the role
		uidVal, _ := c.Get("auth.user_id")
		uid, _ := uidVal.(string)
		if uid != "" {
			slugs := svc.ListRoleSlugsByUser(c.Request.Context(), uid)
			for _, s := range slugs {
				if strings.EqualFold(s, role) {
					c.Next()
					return
				}
			}
		}

		c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"error": "forbidden"})
	}
}

// EntitlementRequired checks the entitlements claim for the given value.
func EntitlementRequired(svc core.Verifier, entitlement string) gin.HandlerFunc {
	required := AuthRequired(svc)
	return func(c *gin.Context) {
		required(c)
		if c.IsAborted() {
			return
		}
		if v, ok := c.Get("auth.entitlements"); ok {
			switch es := v.(type) {
			case []string:
				for _, e := range es {
					if e == entitlement {
						c.Next()
						return
					}
				}
			}
		}
		c.AbortWithStatusJSON(http.StatusPaymentRequired, gin.H{"error": "entitlement_required", "entitlement": entitlement})
	}
}

// RequireAdmin and Admin live in auth.go for discoverability.

// Unified middleware wrapper and SelfOrAdminRequired now live in auth.go to avoid duplication.

// bearer token helper moved to ginutil.BearerToken

func audContains(aud any, want string) bool {
	switch v := aud.(type) {
	case string:
		return v == want
	case []any:
		for _, e := range v {
			if s, ok := e.(string); ok && s == want {
				return true
			}
		}
	case []string:
		for _, s := range v {
			if s == want {
				return true
			}
		}
	}
	return false
}

// audContainsAny checks if token's audience claim contains ANY of the wanted audiences
func audContainsAny(aud any, wantAny []string) bool {
	for _, want := range wantAny {
		if audContains(aud, want) {
			return true
		}
	}
	return false
}

func toUnix(v any) (int64, bool) {
	switch t := v.(type) {
	case float64:
		return int64(t), true
	case int64:
		return t, true
	}
	return 0, false
}
