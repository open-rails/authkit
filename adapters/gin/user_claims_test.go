package authkitgin_test

import (
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	authkitgin "github.com/open-rails/authkit/adapters/gin"
	"github.com/open-rails/authkit/iam"
	"github.com/open-rails/authkit/verify"
)

var _ func(*gin.Context) (verify.UserClaimsData, bool) = authkitgin.UserClaims

func TestUserClaimsReadsRequestContext(t *testing.T) {
	if _, ok := authkitgin.UserClaims(nil); ok {
		t.Fatal("nil Gin context returned a user")
	}
	c, _ := gin.CreateTestContext(httptest.NewRecorder())
	if _, ok := authkitgin.UserClaims(c); ok {
		t.Fatal("missing request returned a user")
	}
	c.Request = httptest.NewRequest("GET", "/", nil)
	if _, ok := authkitgin.UserClaims(c); ok {
		t.Fatal("missing claims returned a user")
	}
	c.Request = c.Request.WithContext(verify.SetClaims(c.Request.Context(), verify.Claims{
		UserID: "writer", Email: "writer@example.com", Entitlements: []string{"premium"}, AMR: []string{"pwd"},
	}))
	got, ok := authkitgin.UserClaims(c)
	if !ok || got.UserID != "writer" || got.Email != "writer@example.com" {
		t.Fatalf("user claims = %+v, %v", got, ok)
	}
	if a, ok := authkitgin.Actor(c); !ok || a.Kind() != iam.ActorUser || a.ID() != "writer" {
		t.Fatalf("actor = %v, %v", a, ok)
	}
	got.Entitlements[0], got.AMR[0] = "changed", "changed"
	stored, _ := verify.ClaimsFromContext(c.Request.Context())
	if stored.Entitlements[0] != "premium" || stored.AMR[0] != "pwd" {
		t.Fatal("adapter result mutated verified request claims")
	}
	c.Request = c.Request.WithContext(verify.SetClaims(c.Request.Context(), verify.Claims{
		UserID: "writer", TokenType: verify.APIKeyPrincipalType,
	}))
	if _, ok := authkitgin.UserClaims(c); ok {
		t.Fatal("machine principal returned a user")
	}
	if _, ok := authkitgin.Actor(c); ok {
		t.Fatal("API key claims without a key id returned an actor")
	}
	if _, ok := authkitgin.Actor(nil); ok {
		t.Fatal("nil Gin context returned an actor")
	}
}
