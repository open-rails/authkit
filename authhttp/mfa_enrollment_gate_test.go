package authhttp

import (
	"context"
	"crypto"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	jwt "github.com/golang-jwt/jwt/v5"
	authkit "github.com/open-rails/authkit"
	"github.com/open-rails/authkit/embedded"
	"github.com/open-rails/authkit/jwtkit"
	"github.com/open-rails/authkit/verify"
	"github.com/stretchr/testify/require"
)

// mfaGateTestConfig builds a server config with an explicit, test-controlled
// signing key (so the test can mint tokens independently of NewServer/embedded.New's
// own key resolution) and the given TwoFactor policy.
func mfaGateTestConfig(t *testing.T, mode authkit.TwoFactorMode) (embedded.Config, jwtkit.Signer) {
	t.Helper()
	signer, err := jwtkit.NewRSASigner(2048, "mfa-gate-test-kid")
	require.NoError(t, err)
	cfg := newServerTestConfig()
	cfg.Keys = embedded.KeysConfig{Source: jwtkit.StaticKeySource{
		Active: signer,
		Pubs:   map[string]crypto.PublicKey{signer.KID(): signer.PublicKey()},
	}}
	cfg.TwoFactor = embedded.TwoFactorConfig{Mode: mode}
	return cfg, signer
}

// mintUnenrolledUserToken signs a valid native-user access token carrying no
// mfa_enrolled claim, i.e. exactly what an existing un-enrolled user's session
// looks like on the wire.
func mintUnenrolledUserToken(t *testing.T, signer jwtkit.Signer, cfg embedded.Config) string {
	t.Helper()
	now := time.Now()
	claims := jwt.MapClaims{
		"sub": "test-user-1",
		"iss": cfg.Token.Issuer,
		"aud": cfg.Token.ExpectedAudiences[0],
		"exp": now.Add(time.Hour).Unix(),
		"iat": now.Unix(),
	}
	tok, err := jwtkit.SignWithType(context.Background(), signer, claims, jwtkit.AccessTokenType, true)
	require.NoError(t, err)
	return tok
}

// #240: NewServer must wire verify.WithRequireMFAEnrollment from TwoFactor.Mode.
// Required mode challenges an existing un-enrolled user's still-valid token on
// their next authenticated request; None/Optional modes are unaffected.
func TestNewServer_ConfiguresMFAEnrollmentGate(t *testing.T) {
	cases := []struct {
		name        string
		mode        authkit.TwoFactorMode
		wantBlocked bool
	}{
		{"disabled", embedded.TwoFactorDisabled, false},
		{"optional", embedded.TwoFactorOptional, false},
		{"required", embedded.TwoFactorRequired, true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			cfg, signer := mfaGateTestConfig(t, c.mode)
			srv, err := NewServer(newServerClient(t, cfg, newNoDBPool(t)), WithoutRateLimiter())
			require.NoError(t, err)

			token := mintUnenrolledUserToken(t, signer, cfg)
			h := verify.Required(srv.verifier)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusOK)
			}))

			req := httptest.NewRequest(http.MethodGet, "/orders", nil)
			req.Header.Set("Authorization", "Bearer "+token)
			w := httptest.NewRecorder()
			h.ServeHTTP(w, req)

			if c.wantBlocked {
				require.Equal(t, http.StatusForbidden, w.Code, "un-enrolled user must be challenged in Required mode")
			} else {
				require.Equal(t, http.StatusOK, w.Code, "un-enrolled user must pass when policy is not Required")
			}
		})
	}
}

// #243: the forced-enrollment gate must not lock an un-enrolled user out of the
// 2FA enroll/challenge/verify surface itself — that allowlist is derived from the
// route registry (RouteSpec.MFAEnrollmentExempt), not a hand-maintained list.
func TestNewServer_MFAEnrollmentGateExemptsEnrollRoutes(t *testing.T) {
	cfg, signer := mfaGateTestConfig(t, embedded.TwoFactorRequired)
	srv, err := NewServer(newServerClient(t, cfg, newNoDBPool(t)), WithoutRateLimiter())
	require.NoError(t, err)
	token := mintUnenrolledUserToken(t, signer, cfg)

	h := verify.Required(srv.verifier)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	for _, c := range []struct{ method, path string }{
		{http.MethodGet, "/user/2fa"},
		{http.MethodPost, "/user/2fa/backup-codes"},
		{http.MethodPost, "/2fa/challenge"},
		{http.MethodPost, "/2fa/verify"},
		{http.MethodPost, "/api/v1/2fa/verify"}, // suffix-matched under a host mount prefix
	} {
		req := httptest.NewRequest(c.method, c.path, nil)
		req.Header.Set("Authorization", "Bearer "+token)
		w := httptest.NewRecorder()
		h.ServeHTTP(w, req)
		require.Equalf(t, http.StatusOK, w.Code, "%s %s must stay reachable to an un-enrolled user", c.method, c.path)
	}
}

// #243: the exempt set NewServer derives is exactly the routes tagged
// MFAEnrollmentExempt in the route registry — the single source of truth — so a
// renamed/added enroll route stays consistent by construction instead of
// requiring a parallel suffix list to be updated by hand.
func TestAPIRoutes_MFAEnrollmentExemptPathsMatchRegistry(t *testing.T) {
	srv := newTestService(t)
	got := mfaEnrollmentExemptPaths(srv.APIRoutes())
	want := []string{"/user/2fa", "/user/2fa/backup-codes", "/2fa/challenge", "/2fa/verify"}
	require.ElementsMatch(t, want, got)
}
