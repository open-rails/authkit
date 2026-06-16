package authhttp

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	core "github.com/open-rails/authkit/core"
	jwtkit "github.com/open-rails/authkit/jwt"
	"github.com/stretchr/testify/require"
)

func TestCleanStrings(t *testing.T) {
	require.Equal(t, []string{"endpoint:deploy", "secrets:write"},
		cleanStrings([]string{" endpoint:deploy ", "", "secrets:write", "endpoint:deploy"}))
	require.Empty(t, cleanStrings(nil))
	require.Empty(t, cleanStrings([]string{"  ", ""}))
}

func TestClaimsIsService(t *testing.T) {
	require.True(t, Claims{TokenType: "service"}.IsService())
	require.True(t, Claims{TokenType: "Service"}.IsService())
	require.False(t, Claims{}.IsService())
	require.False(t, Claims{TokenType: "user"}.IsService())
	// A service principal is not a delegated principal.
	require.False(t, Claims{TokenType: "service"}.IsDelegated())
}

func TestAccessTokenViewIncludesResources(t *testing.T) {
	created := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	view := toAccessTokenView(core.ServiceToken{
		ID:          "tok_1",
		KeyID:       "key_1",
		Name:        "ci",
		Permissions: []string{"openrails:credits:spend"},
		Resources: []core.ServiceTokenResource{
			{Kind: "openrails.merchant", ID: "tensorhub"},
			{Kind: "openrails.customer", ID: "cozy-art"},
		},
		CreatedAt: created,
	})
	require.Equal(t, []core.ServiceTokenResource{
		{Kind: "openrails.merchant", ID: "tensorhub"},
		{Kind: "openrails.customer", ID: "cozy-art"},
	}, view.Resources)
	require.Equal(t, "2026-01-02T03:04:05Z", view.CreatedAt)
}

// TestServiceTokenMiddlewareDetectionAndFallthrough verifies that the Required middleware
// routes tokens carrying the configured service-token marker to the (DB-backed) service-token path,
// while ordinary JWTs still fall through to JWT verification even when a service token
// prefix is configured.
func TestServiceTokenMiddlewareDetectionAndFallthrough(t *testing.T) {
	signer, err := jwtkit.NewRSASigner(2048, "kid")
	require.NoError(t, err)

	ok := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusOK) })
	call := func(v *Verifier, bearer string) *httptest.ResponseRecorder {
		w := httptest.NewRecorder()
		r := httptest.NewRequest(http.MethodGet, "/", nil)
		r.Header.Set("Authorization", "Bearer "+bearer)
		Required(v)(ok).ServeHTTP(w, r)
		return w
	}
	validJWT := func() string {
		return signToken(t, signer, map[string]any{
			"iss": "https://example.com",
			"sub": "user",
			"aud": "test-app",
			"iat": time.Now().Unix(),
			"exp": time.Now().Add(time.Hour).Unix(),
		})
	}

	t.Run("branded prefix: valid JWT falls through and passes", func(t *testing.T) {
		v := newTestVerifier(t, signer, "https://example.com", []string{"test-app"}, WithServiceTokenPrefix("cozy"))
		require.Equal(t, http.StatusOK, call(v, validJWT()).Code)
	})

	t.Run("service-token-shaped token is routed to service-token path (not JWT) and rejected without a store", func(t *testing.T) {
		// No service attached -> the service-token path cannot resolve and returns
		// invalid_token. The key point: it is handled by the service-token branch, never
		// parsed as a JWT.
		v := newTestVerifier(t, signer, "https://example.com", []string{"test-app"}, WithServiceTokenPrefix("cozy"))
		w := call(v, "cozy_st_somekeyid_somesecretvalue")
		require.Equal(t, http.StatusUnauthorized, w.Code)
		require.JSONEq(t, `{"error":"invalid_token"}`, w.Body.String())
	})

	t.Run("wrong app prefix is NOT a service token and falls through to JWT verify", func(t *testing.T) {
		// With prefix "cozy" the marker is "cozy_st_"; a bare "st_..." token is
		// not a service token for this app, so it falls through to JWT verification (and
		// fails there as an unparseable JWT).
		v := newTestVerifier(t, signer, "https://example.com", []string{"test-app"}, WithServiceTokenPrefix("cozy"))
		w := call(v, "st_keyid_secret")
		require.Equal(t, http.StatusUnauthorized, w.Code)
		require.JSONEq(t, `{"error":"invalid_token"}`, w.Body.String())
	})

	t.Run("default (empty) prefix detects bare st_", func(t *testing.T) {
		v := newTestVerifier(t, signer, "https://example.com", []string{"test-app"})
		w := call(v, "st_keyid_secret")
		require.Equal(t, http.StatusUnauthorized, w.Code)
		require.JSONEq(t, `{"error":"invalid_token"}`, w.Body.String())
	})
}
