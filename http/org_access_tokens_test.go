package authhttp

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

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

// TestOATMiddlewareDetectionAndFallthrough verifies that the Required middleware
// routes tokens carrying the configured OAT marker to the (DB-backed) OAT path,
// while ordinary JWTs still fall through to JWT verification even when an OAT
// prefix is configured.
func TestOATMiddlewareDetectionAndFallthrough(t *testing.T) {
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
		v := newTestVerifier(t, signer, "https://example.com", []string{"test-app"}, WithTokenPrefix("cozy"))
		require.Equal(t, http.StatusOK, call(v, validJWT()).Code)
	})

	t.Run("OAT-shaped token is routed to OAT path (not JWT) and rejected without a store", func(t *testing.T) {
		// No service attached -> the OAT path cannot resolve and returns
		// invalid_token. The key point: it is handled by the OAT branch, never
		// parsed as a JWT.
		v := newTestVerifier(t, signer, "https://example.com", []string{"test-app"}, WithTokenPrefix("cozy"))
		w := call(v, "cozy_oat_somekeyid_somesecretvalue")
		require.Equal(t, http.StatusUnauthorized, w.Code)
		require.JSONEq(t, `{"error":"invalid_token"}`, w.Body.String())
	})

	t.Run("wrong app prefix is NOT an OAT and falls through to JWT verify", func(t *testing.T) {
		// With prefix "cozy" the marker is "cozy_oat_"; a bare "oat_..." token is
		// not an OAT for this app, so it falls through to JWT verification (and
		// fails there as an unparseable JWT).
		v := newTestVerifier(t, signer, "https://example.com", []string{"test-app"}, WithTokenPrefix("cozy"))
		w := call(v, "oat_keyid_secret")
		require.Equal(t, http.StatusUnauthorized, w.Code)
		require.JSONEq(t, `{"error":"invalid_token"}`, w.Body.String())
	})

	t.Run("default (empty) prefix detects bare oat_", func(t *testing.T) {
		v := newTestVerifier(t, signer, "https://example.com", []string{"test-app"})
		w := call(v, "oat_keyid_secret")
		require.Equal(t, http.StatusUnauthorized, w.Code)
		require.JSONEq(t, `{"error":"invalid_token"}`, w.Body.String())
	})
}
