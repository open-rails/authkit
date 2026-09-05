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
	"github.com/open-rails/authkit/password"
	"github.com/open-rails/authkit/ratelimit"
	"github.com/open-rails/authkit/verify"
)

// TestLazyLoadedIssuerEnforcesExpectedAudience pins ak#324 item 1: on the
// NewServer path (no LoadRemoteApplications call) a lazily-loaded remote
// application is registered with Config.Token.ExpectedAudiences, so a token it
// minted for a different audience is rejected.
func TestLazyLoadedIssuerEnforcesExpectedAudience(t *testing.T) {
	pool := testdb.Pool(t)
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

	_, err = srv.Verifier().Verify(context.Background(), mint("other-app"))
	require.Error(t, err, "wrong audience must be rejected by a lazily-loaded issuer")
	_, err = srv.Verifier().Verify(context.Background(), mint("test-app"))
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
	srv, err := NewServer(newServerClient(t, cfg, testdb.Pool(t)), WithoutRateLimiter())
	require.NoError(t, err)
	h := srv.apiHandler()

	for path, want := range map[string]string{
		"/verify/confirm?token=sekrit&channel=email&return_to=/next": "https://app.example/verify#channel=email&return_to=%2Fnext&status=ready&token=sekrit",
		"/verify/confirm?token=sekrit&channel=phone":                 "https://app.example/verify#channel=phone&status=ready&token=sekrit",
		"/password/reset/confirm?token=sekrit&channel=email":         "https://app.example/reset#channel=email&status=ready&token=sekrit",
		"/password/reset/confirm?token=sekrit":                       "https://app.example/reset#status=ready&token=sekrit",
		"/password/reset/confirm":                                    "https://app.example/reset#status=invalid_request",
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
	pool := testdb.Pool(t)
	rdb := testdb.ScratchRedis(t)
	srv, err := NewServer(newServerClient(t, newServerTestConfig(), pool, embedded.WithRedis(rdb)), WithoutRateLimiter())
	require.NoError(t, err)

	w := serveJSON(srv, http.MethodPost, "/verify/confirm", `{"identifier":"nobody@example.com","code":"000000"}`)
	require.Equal(t, http.StatusBadRequest, w.Code, w.Body.String())
	require.Contains(t, w.Body.String(), "invalid_or_expired_code")

	require.NoError(t, rdb.Close())
	for _, tc := range []struct{ path, body string }{
		{"/verify/confirm", `{"identifier":"nobody@example.com","code":"000000"}`},
		{"/verify/confirm", `{"identifier":"+15555550100","code":"000000"}`},
		{"/password/reset/confirm", `{"token":"nope","new_password":"Correct-password-12345"}`},
	} {
		w := serveJSON(srv, http.MethodPost, tc.path, tc.body)
		require.Equal(t, http.StatusInternalServerError, w.Code, tc.path+": "+w.Body.String())
		require.Contains(t, w.Body.String(), "database_error", tc.path)
	}
}

// TestContactChangeRateLimitPrecedesPasswordCheck pins ak#324 item 4: the
// authenticated email/phone change request consumes its own rate-limit bucket
// BEFORE the password / fresh-auth check, so a wrong password cannot be retried
// past the bucket and a limited request gets one 429, not a 401 with a
// superfluous second WriteHeader.
func TestContactChangeRateLimitPrecedesPasswordCheck(t *testing.T) {
	pool := testdb.Pool(t)
	ctx := context.Background()
	srv, err := NewServer(
		newServerClient(t, newServerTestConfig(), pool, embedded.WithEmailSender(&captureEmailSender{}), embedded.WithSMSSender(&captureSMSSender{})),
		WithRateLimitOverrides(map[string]ratelimit.Limit{
			RLVerifyRequest: {Limit: 100, Window: time.Hour},
		}),
	)
	require.NoError(t, err)
	user, err := srv.svc.CreateUser(ctx, uniqueEmail("rl-order"), "rlorder"+uniqueSuffix()[8:])
	require.NoError(t, err)
	t.Cleanup(func() { _, _ = pool.Exec(ctx, `DELETE FROM profiles.users WHERE id=$1::uuid`, user.ID) })
	hash, err := password.HashArgon2id("Correct-password-12345")
	require.NoError(t, err)
	require.NoError(t, srv.svc.UpsertPasswordHash(ctx, user.ID, hash, "argon2id", nil))
	sid, _, _, err := srv.svc.IssueRefreshSession(ctx, user.ID, "test", nil)
	require.NoError(t, err)
	// Age the session past the fresh-auth window so the password path runs.
	_, err = pool.Exec(ctx, `UPDATE profiles.refresh_sessions SET last_authenticated_at = now() - interval '1 hour' WHERE id=$1::uuid`, sid)
	require.NoError(t, err)
	token, _, err := srv.svc.MintAccessToken(ctx, user.ID, map[string]any{"sid": sid})
	require.NoError(t, err)

	// Both channels share the one change bucket now (#312), so each case gets
	// its own client IP.
	for _, tc := range []struct {
		ip   string
		body func() string
	}{
		{"203.0.113.40:1234", func() string {
			return `{"identifier":"` + uniqueEmail("rl-new") + `","password":"wrong-password-12345"}`
		}},
		{"203.0.113.41:1234", func() string { return `{"identifier":"` + uniquePhone() + `","password":"wrong-password-12345"}` }},
	} {
		first := serveAuthJSONFrom(srv, http.MethodPost, "/verify/request", tc.body(), token, tc.ip)
		require.GreaterOrEqual(t, first.Code, 400, tc.ip)
		require.NotEqual(t, http.StatusTooManyRequests, first.Code, tc.ip)
		second := serveAuthJSONFrom(srv, http.MethodPost, "/verify/request", tc.body(), token, tc.ip)
		require.Equal(t, http.StatusTooManyRequests, second.Code, tc.ip+": the change bucket must trip before the password check: "+second.Body.String())
	}
}

// TestMountAnchorsMFAEnrollmentExemptRoutes pins ak#324 item 5: after
// MountHandler, the enrollment-only token reaches the mounted 2FA surface and
// nothing else — not even a host route that happens to end in "/user/2fa".
func TestMountAnchorsMFAEnrollmentExemptRoutes(t *testing.T) {
	pool := testdb.Pool(t)
	ctx := context.Background()
	srv, err := NewServer(newServerClient(t, newServerTestConfig(), pool), WithoutRateLimiter())
	require.NoError(t, err)
	mounted, err := MountHandler(srv, MountOptions{APIPrefix: "/api/v1"})
	require.NoError(t, err)
	user, err := srv.svc.CreateUser(ctx, uniqueEmail("mfa-anchor"), "mfaanchor"+uniqueSuffix()[8:])
	require.NoError(t, err)
	t.Cleanup(func() { _, _ = pool.Exec(ctx, `DELETE FROM profiles.users WHERE id=$1::uuid`, user.ID) })
	token, _, err := srv.svc.Mint2FAEnrollmentToken(ctx, user.ID)
	require.NoError(t, err)
	get := func(h http.Handler, path string) int {
		w := httptest.NewRecorder()
		r := httptest.NewRequest(http.MethodGet, path, nil)
		r.Header.Set("Authorization", "Bearer "+token)
		h.ServeHTTP(w, r)
		return w.Code
	}

	require.Equal(t, http.StatusOK, get(mounted, "/api/v1/user/2fa"), "the mounted enrollment surface stays reachable")
	require.Equal(t, http.StatusForbidden, get(mounted, "/api/v1/me"), "everything else stays gated")
	host := verify.Required(srv.Verifier())(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) }))
	require.Equal(t, http.StatusForbidden, get(host, "/host/user/2fa"), "a host route that merely ends in /user/2fa is not exempt")
}
