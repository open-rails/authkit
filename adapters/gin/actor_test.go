package authkitgin_test

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	authkitgin "github.com/open-rails/authkit/adapters/gin"
	"github.com/open-rails/authkit/authtest"
	"github.com/open-rails/authkit/iam"
	"github.com/open-rails/authkit/verify"
	"github.com/stretchr/testify/require"
)

// A gin handler behind Required reads the verified caller from the request
// context, the same call net/http and Fiber handlers make.
func TestActorFromContextBehindRequired(t *testing.T) {
	issuer := authtest.NewTestIssuer()
	defer issuer.Close()
	verifier := verify.NewVerifier()
	require.NoError(t, verifier.AddIssuer(issuer.URL(), []string{issuer.Audience()}, verify.IssuerOptions{JWKSURI: issuer.URL() + "/.well-known/jwks.json", IsLocal: true}))
	router := gin.New()
	router.GET("/", authkitgin.Required(verifier), func(c *gin.Context) {
		actor, ok := verify.ActorFromContext(c.Request.Context())
		require.True(t, ok)
		require.Equal(t, iam.ActorUser, actor.Kind())
		c.String(http.StatusOK, actor.ID())
	})
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.Header.Set("Authorization", "Bearer "+issuer.CreateToken("user-1", "user@example.com"))
	router.ServeHTTP(w, r)
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	require.Equal(t, "user-1", w.Body.String())

	w = httptest.NewRecorder()
	router.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/", nil))
	require.Equal(t, http.StatusUnauthorized, w.Code, "Required aborts before the handler")
}
