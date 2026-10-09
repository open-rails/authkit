package authkitgin_test

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	authkitgin "github.com/open-rails/authkit/adapters/gin"
	"github.com/open-rails/authkit/iam"
	"github.com/open-rails/authkit/internal/testissuer"
	"github.com/open-rails/authkit/verify"
	"github.com/stretchr/testify/require"
)

// A gin handler behind Required reads the verified caller from the request
// context, the same call net/http and Fiber handlers make.
func TestIdentityFromContextBehindRequired(t *testing.T) {
	issuer := testissuer.New(t)
	verifier := verify.NewVerifier()
	require.NoError(t, verifier.AddIssuer(issuer.URL(), []string{issuer.Audience()}, verify.IssuerOptions{JWKSURI: issuer.URL() + "/.well-known/jwks.json", IsLocal: true}))
	router := gin.New()
	router.GET("/", authkitgin.Required(verifier), func(c *gin.Context) {
		who, ok := verify.IdentityFromContext(c.Request.Context())
		require.True(t, ok)
		state, bound := iam.StateOf(who)
		require.True(t, bound && state.IsUser(), "a gate's identity carries AuthKit's state")
		c.String(http.StatusOK, who.Subject)
	})
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.Header.Set("Authorization", "Bearer "+issuer.Token("user-1", "user@example.com", nil))
	router.ServeHTTP(w, r)
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	require.Equal(t, "user-1", w.Body.String())

	w = httptest.NewRecorder()
	router.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/", nil))
	require.Equal(t, http.StatusUnauthorized, w.Code, "Required aborts before the handler")
}
