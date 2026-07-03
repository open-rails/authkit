package authkitgin

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/require"

	"github.com/open-rails/authkit/authtest"
	"github.com/open-rails/authkit/verify"
)

// #209: the gin-native Required/Optional middleware — the ergonomics all three
// consumer apps hand-rolled — must gate exactly like the verify originals: 401 +
// abort for a missing/invalid token on Required, anonymous pass-through on
// Optional, and claims in the request context on success.
func TestGinNativeRequiredOptional(t *testing.T) {
	issuer := authtest.NewTestIssuer()
	t.Cleanup(issuer.Close)
	v := verify.NewVerifier(verify.WithAlgorithms("RS256"), verify.WithSkew(60*time.Second))
	require.NoError(t, v.AddIssuer(issuer.URL(), []string{issuer.Audience()}, verify.IssuerOptions{
		JWKSURI: issuer.URL() + "/.well-known/jwks.json",
	}))

	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.GET("/required", Required(v), func(c *gin.Context) {
		cl, ok := verify.ClaimsFromContext(c.Request.Context())
		require.True(t, ok, "claims must be in context behind Required")
		c.String(http.StatusOK, cl.UserID)
	})
	r.GET("/optional", Optional(v), func(c *gin.Context) {
		if cl, ok := verify.ClaimsFromContext(c.Request.Context()); ok {
			c.String(http.StatusOK, cl.UserID)
			return
		}
		c.String(http.StatusOK, "anonymous")
	})

	do := func(path, token string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodGet, path, nil)
		if token != "" {
			req.Header.Set("Authorization", "Bearer "+token)
		}
		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)
		return w
	}

	// Required: no token → 401, handler never runs.
	w := do("/required", "")
	require.Equal(t, http.StatusUnauthorized, w.Code, w.Body.String())

	// Required: valid token → 200 with the token's subject.
	token := issuer.CreateToken("user-209", "u209@example.com")
	w = do("/required", token)
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	require.Equal(t, "user-209", w.Body.String())

	// Optional: no token → anonymous pass-through.
	w = do("/optional", "")
	require.Equal(t, http.StatusOK, w.Code)
	require.Equal(t, "anonymous", w.Body.String())

	// Optional: valid token → claims available.
	w = do("/optional", token)
	require.Equal(t, http.StatusOK, w.Code)
	require.Equal(t, "user-209", w.Body.String())

	// Optional: a PRESENT-but-invalid token must still be rejected (not treated
	// as anonymous) — same contract as verify.Optional.
	w = do("/optional", issuer.CreateExpiredToken("user-209", "u209@example.com"))
	require.Equal(t, http.StatusUnauthorized, w.Code, w.Body.String())
}
