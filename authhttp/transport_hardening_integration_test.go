package authhttp

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	authkit "github.com/open-rails/authkit"
	"github.com/open-rails/authkit/embedded"
	authcore "github.com/open-rails/authkit/internal/authcore"
	"github.com/open-rails/authkit/internal/testdb"
	"github.com/open-rails/authkit/jwtkit"
)

// TestLazyLoadedIssuerEnforcesExpectedAudience pins ak#324 item 1: on the
// NewServer path (no LoadRemoteApplications call) a lazily-loaded remote
// application is registered with Config.Token.ExpectedAudiences, so a token it
// minted for a different audience is rejected.
func TestLazyLoadedIssuerEnforcesExpectedAudience(t *testing.T) {
	pool := newServerTestPool(t)
	ctx := context.Background()
	client := newServerClient(t, newServerTestConfig(), pool) // dev: loopback JWKS allowed
	srv, err := NewServer(client)
	require.NoError(t, err)
	core := embedded.Unwrap(client)
	gid, err := core.EnsureRootGroup(ctx)
	require.NoError(t, err)

	signer, err := jwtkit.NewRSASigner(2048, "aud-kid")
	require.NoError(t, err)
	jwks := newLoopbackJWKSServer(t, signer)
	ra, err := core.UpsertRemoteApplication(ctx, authcore.RemoteApplication{
		Slug: fmt.Sprintf("aud-%d", time.Now().UnixNano()), PermissionGroupID: gid,
		Issuer: jwks.URL, JWKSURI: jwks.URL + "/.well-known/jwks.json", Enabled: true,
	})
	require.NoError(t, err)
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DELETE FROM profiles.remote_applications WHERE id=$1::uuid`, ra.ID)
	})
	mint := func(aud string) string {
		tok, err := authcore.MintDelegatedAccessToken(ctx, signer, authkit.DelegatedAccessParams{
			Issuer: jwks.URL, Audiences: []string{aud}, DelegatedSubject: "u1", TTL: time.Minute,
		})
		require.NoError(t, err)
		return tok
	}

	_, err = srv.Verifier().Verify(mint("other-app"))
	require.Error(t, err, "wrong audience must be rejected by a lazily-loaded issuer")
	_, err = srv.Verifier().Verify(mint("test-app"))
	require.NoError(t, err)
}

// TestLinkLandingUsesFragmentAndNoStore pins ak#324 item 2: the reset/verify
// link token rides the URL fragment of the SPA redirect, never the query, and
// the redirect is uncacheable.
func TestLinkLandingUsesFragmentAndNoStore(t *testing.T) {
	cfg := newServerTestConfig()
	cfg.Frontend.BaseURL = "https://app.example/"
	cfg.Frontend.VerifyPath = "/verify"
	cfg.Frontend.PasswordResetPath = "/reset"
	srv, err := NewServer(newServerClient(t, cfg, newNoDBPool(t)), WithoutRateLimiter())
	require.NoError(t, err)
	h := srv.APIHandler()

	for path, want := range map[string]string{
		"/email/verify/confirm?token=sekrit&return_to=/next": "https://app.example/verify#channel=email&return_to=%2Fnext&status=ready&token=sekrit",
		"/phone/verify/confirm?token=sekrit":                 "https://app.example/verify#channel=phone&status=ready&token=sekrit",
		"/email/password/reset/confirm?token=sekrit":         "https://app.example/reset#channel=email&status=ready&token=sekrit",
		"/phone/password/reset/confirm?token=sekrit":         "https://app.example/reset#channel=phone&status=ready&token=sekrit",
		"/email/password/reset/confirm":                      "https://app.example/reset#channel=email&status=invalid_request",
	} {
		w := httptest.NewRecorder()
		h.ServeHTTP(w, httptest.NewRequest(http.MethodGet, path, nil))
		require.Equal(t, http.StatusFound, w.Code, path)
		require.Equal(t, want, w.Header().Get("Location"), path)
		require.NotContains(t, w.Header().Get("Location"), "?token=", path)
		require.Equal(t, "no-store", w.Header().Get("Cache-Control"), path)
	}
}

// TestConfirmBackendFailureIs500NotAGuess pins ak#324 item 3: with the store
// down, every verify/reset confirm path is a 500 backend failure and never a
// counted bad guess; with the store up, a wrong code is still a 400 guess.
func TestConfirmBackendFailureIs500NotAGuess(t *testing.T) {
	pool := newServerTestPool(t)
	rdb := testdb.ScratchRedis(t)
	srv, err := NewServer(newServerClient(t, newServerTestConfig(), pool, embedded.WithRedis(rdb)), WithoutRateLimiter())
	require.NoError(t, err)

	w := serveJSON(srv, http.MethodPost, "/email/verify/confirm", `{"email":"nobody@example.com","code":"000000"}`)
	require.Equal(t, http.StatusBadRequest, w.Code, w.Body.String())
	require.Contains(t, w.Body.String(), "invalid_or_expired_code")

	require.NoError(t, rdb.Close())
	for path, body := range map[string]string{
		"/email/verify/confirm":         `{"email":"nobody@example.com","code":"000000"}`,
		"/phone/verify/confirm":         `{"phone_number":"+15555550100","code":"000000"}`,
		"/email/password/reset/confirm": `{"token":"nope","new_password":"Correct-password-12345"}`,
		"/phone/password/reset/confirm": `{"token":"nope","new_password":"Correct-password-12345"}`,
	} {
		w := serveJSON(srv, http.MethodPost, path, body)
		require.Equal(t, http.StatusInternalServerError, w.Code, path+": "+w.Body.String())
		require.Contains(t, w.Body.String(), "database_error", path)
	}
}
