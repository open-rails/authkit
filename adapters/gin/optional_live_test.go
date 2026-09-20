package authkitgin_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/open-rails/authkit"
	authkitgin "github.com/open-rails/authkit/adapters/gin"
	"github.com/open-rails/authkit/authtest"
	"github.com/open-rails/authkit/verify"
	"github.com/stretchr/testify/require"
)

type ginLiveDirectory struct {
	calls   int
	allowed bool
}

func (s *ginLiveDirectory) UserLivenessByIDs(_ context.Context, ids []string) (map[string]authkit.UserLiveness, error) {
	s.calls++
	return map[string]authkit.UserLiveness{ids[0]: {ID: ids[0], Allowed: s.allowed, Username: "fresh"}}, nil
}

func TestOptionalLive(t *testing.T) {
	middleware, err := authkitgin.OptionalLive(nil)
	require.Nil(t, middleware)
	require.ErrorIs(t, err, verify.ErrLivenessUnconfigured)
	issuer := authtest.NewTestIssuer()
	defer issuer.Close()
	source := &ginLiveDirectory{allowed: true}
	verifier := verify.NewVerifier().WithLiveness(source)
	require.NoError(t, verifier.AddIssuer(issuer.URL(), []string{issuer.Audience()}, verify.IssuerOptions{JWKSURI: issuer.URL() + "/.well-known/jwks.json", IsLocal: true}))
	middleware, err = authkitgin.OptionalLive(verifier)
	require.NoError(t, err)
	router := gin.New()
	router.Use(middleware)
	router.GET("/", func(c *gin.Context) {
		user, ok := authkitgin.UserClaims(c)
		if !ok {
			c.String(http.StatusOK, "anonymous")
			return
		}
		c.String(http.StatusOK, user.Username)
	})
	for _, tc := range []struct {
		header, body  string
		status, calls int
	}{
		{body: "anonymous", status: 200, calls: 0},
		{header: "Bearer invalid", status: 401, calls: 0},
		{header: "Bearer " + issuer.CreateToken("user-1", "old@test"), body: "fresh", status: 200, calls: 1},
	} {
		response := httptest.NewRecorder()
		request := httptest.NewRequest(http.MethodGet, "/", nil)
		request.Header.Set("Authorization", tc.header)
		router.ServeHTTP(response, request)
		require.Equal(t, tc.status, response.Code)
		if tc.body != "" {
			require.Equal(t, tc.body, response.Body.String())
		}
		require.Equal(t, tc.calls, source.calls)
	}
	source.allowed = false
	response := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, "/", nil)
	request.Header.Set("Authorization", "Bearer "+issuer.CreateToken("user-1", "old@test"))
	router.ServeHTTP(response, request)
	require.Equal(t, http.StatusUnauthorized, response.Code)
	require.Equal(t, 2, source.calls)
}
