package authgin

import (
	"context"
	"errors"
	"strings"

	"github.com/gin-gonic/gin"
)

// Claims is a typed view of authenticated user information attached by middleware.
type Claims struct {
	UserID          string
	Email           string
	EmailVerified   bool
	Username        string
	DiscordUsername string
	SessionID       string
	Roles           []string
	Entitlements    []string
}

func (c Claims) HasRole(role string) bool {
	for _, r := range c.Roles {
		if strings.EqualFold(r, role) {
			return true
		}
	}
	return false
}

func (c Claims) HasEntitlement(ent string) bool {
	for _, e := range c.Entitlements {
		if strings.EqualFold(e, ent) {
			return true
		}
	}
	return false
}

// unexported context key
type claimsCtxKey struct{}

// SetClaims returns a child context with claims attached.
func SetClaims(ctx context.Context, cl Claims) context.Context {
	return context.WithValue(ctx, claimsCtxKey{}, cl)
}

// FromContext extracts claims from a standard context.
func FromContext(ctx context.Context) (Claims, bool) {
	v := ctx.Value(claimsCtxKey{})
	if v == nil {
		return Claims{}, false
	}
	cl, ok := v.(Claims)
	return cl, ok
}

// Claims returns claims from Gin context if present.
func ClaimsFromGin(c *gin.Context) (Claims, bool) {
	if v, ok := c.Get("authkit.claims"); ok {
		if cl, ok := v.(Claims); ok {
			return cl, true
		}
	}
	return FromContext(c.Request.Context())
}

// Claims returns claims or an error if not present/unauthenticated.
// GetClaims returns claims or an error if not present/unauthenticated.
func GetClaims(c *gin.Context) (Claims, error) {
	if cl, ok := ClaimsFromGin(c); ok {
		return cl, nil
	}
	return Claims{}, errors.New("unauthenticated")
}

// UserID is a typed accessor for the authenticated user's id.
func UserID(c *gin.Context) (string, bool) {
	if cl, ok := ClaimsFromGin(c); ok && cl.UserID != "" {
		return cl.UserID, true
	}
	return "", false
}

// Email is a typed accessor for the authenticated user's email.
func Email(c *gin.Context) (string, bool) {
	if cl, ok := ClaimsFromGin(c); ok && cl.Email != "" {
		return cl.Email, true
	}
	return "", false
}

// Roles returns the roles array (may be empty).
func Roles(c *gin.Context) []string {
	if cl, ok := ClaimsFromGin(c); ok {
		return cl.Roles
	}
	return nil
}

// Entitlements returns the entitlements array (may be empty).
func Entitlements(c *gin.Context) []string {
	if cl, ok := ClaimsFromGin(c); ok {
		return cl.Entitlements
	}
	return nil
}
