package authhttp

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/require"

	core "github.com/open-rails/authkit/core"
)

type captureSMSSender struct {
	passwordResetToken string
}

func (s *captureSMSSender) SendVerification(context.Context, string, core.VerificationMessage) error {
	return nil
}

func (s *captureSMSSender) SendPasswordResetLink(_ context.Context, _ string, token string) error {
	s.passwordResetToken = token
	return nil
}

func (s *captureSMSSender) SendLoginCode(context.Context, string, string) error {
	return nil
}

func TestPhonePasswordResetConfirmLinkConsumesToken(t *testing.T) {
	ctx := context.Background()
	pool := routeCleanupPG(t)
	const phone = "+15555550196"
	const username = "phoneconfirm196"
	_, _ = pool.Exec(ctx, `DELETE FROM profiles.users WHERE username=$1 OR phone_number=$2`, username, phone)

	cfg := core.Config{
		Token: core.TokenConfig{
			Issuer:            "https://example.com",
			IssuedAudiences:   []string{"test-app"},
			ExpectedAudiences: []string{"test-app"},
		},
		Frontend:     core.FrontendConfig{BaseURL: "https://example.com"},
		Registration: core.RegistrationConfig{Verification: core.RegistrationVerificationNone},
	}
	sms := &captureSMSSender{}
	svc, err := NewServer(cfg, pool, WithSMSSender(sms))
	require.NoError(t, err)

	_, err = svc.svc.CreatePendingPhoneRegistration(ctx, phone, username, "argon2id$hash")
	require.NoError(t, err)
	t.Cleanup(func() {
		_, _ = pool.Exec(ctx, `DELETE FROM profiles.users WHERE username=$1 OR phone_number=$2`, username, phone)
	})

	h := svc.APIHandler()
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/phone/password/reset/request", bytes.NewReader([]byte(`{"phone_number":"`+phone+`"}`)))
	r.Header.Set("Content-Type", "application/json")
	h.ServeHTTP(w, r)
	require.Equal(t, http.StatusAccepted, w.Code, w.Body.String())
	require.NotEmpty(t, sms.passwordResetToken)

	w = httptest.NewRecorder()
	body := []byte(`{"token":"` + sms.passwordResetToken + `"}`)
	r = httptest.NewRequest(http.MethodPost, "/phone/password/reset/confirm-link", bytes.NewReader(body))
	r.Header.Set("Content-Type", "application/json")
	h.ServeHTTP(w, r)
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())

	var resp struct {
		OK           bool   `json:"ok"`
		ResetSession string `json:"reset_session"`
	}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	require.True(t, resp.OK)
	require.NotEmpty(t, resp.ResetSession)
}

func TestRouteCleanupHardCutsThroughAPIHandler(t *testing.T) {
	svc := newTestService(t)
	h := svc.APIHandler()

	cases := []struct {
		method string
		path   string
		want   int
	}{
		{http.MethodGet, "/identity-providers", http.StatusOK},
		{http.MethodGet, "/providers", http.StatusNotFound},
		{http.MethodGet, "/me/bootstrap", http.StatusUnauthorized},
		{http.MethodGet, "/user/bootstrap", http.StatusNotFound},
		{http.MethodGet, "/me/org-invites", http.StatusUnauthorized},
		{http.MethodGet, "/me/invites", http.StatusNotFound},
		{http.MethodPost, "/token/org", http.StatusNotFound},
	}
	for _, tc := range cases {
		t.Run(tc.method+" "+tc.path, func(t *testing.T) {
			w := httptest.NewRecorder()
			r := httptest.NewRequest(tc.method, tc.path, nil)
			h.ServeHTTP(w, r)
			require.Equal(t, tc.want, w.Code, w.Body.String())
		})
	}
}

// TestNamespaceLookupReturnsOwnerForTakenSlug: GET /namespaces/{slug} for a slug
// owned by a user returns that user; the org side is absent and neither kind is
// claimable. Usernames and org slugs share ONE owner-namespace (#96 — see
// ownerSlugAvailable, which checks both), so a username and a same-slug org can
// never both be created through the public API; the slug is simply taken.
func TestNamespaceLookupReturnsOwnerForTakenSlug(t *testing.T) {
	ctx := context.Background()
	pool := routeCleanupPG(t)
	const slug = "same-slug-96"
	_, _ = pool.Exec(ctx, `DELETE FROM profiles.orgs WHERE slug=$1`, slug)
	_, _ = pool.Exec(ctx, `DELETE FROM profiles.users WHERE username=$1`, slug)

	cfg := core.Config{
		Token: core.TokenConfig{
			Issuer:            "https://example.com",
			IssuedAudiences:   []string{"test-app"},
			ExpectedAudiences: []string{"test-app"},
		},
		Frontend:     core.FrontendConfig{BaseURL: "https://example.com"},
		Registration: core.RegistrationConfig{Verification: core.RegistrationVerificationNone},
	}
	svc, err := NewServer(cfg, pool)
	require.NoError(t, err)

	user, err := svc.svc.CreateUser(ctx, slug+"@example.com", slug)
	require.NoError(t, err)
	require.NotEmpty(t, user.ID)
	// Creating an org with the same slug is rejected — the username already holds it.
	_, err = svc.svc.CreateOrgForUser(ctx, core.CreateOrgForUserRequest{Slug: slug, OwnerUserID: user.ID})
	require.ErrorIs(t, err, core.ErrOwnerSlugTaken)
	t.Cleanup(func() {
		_, _ = pool.Exec(ctx, `DELETE FROM profiles.orgs WHERE slug=$1`, slug)
		_, _ = pool.Exec(ctx, `DELETE FROM profiles.users WHERE username=$1`, slug)
	})

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/namespaces/"+slug, nil)
	svc.APIHandler().ServeHTTP(w, r)
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())

	var resp struct {
		User *struct {
			Username string `json:"username"`
		} `json:"user"`
		Org *struct {
			Slug string `json:"slug"`
		} `json:"org"`
		Claimable struct {
			User bool `json:"user"`
			Org  bool `json:"org"`
		} `json:"claimable"`
	}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	require.NotNil(t, resp.User)
	require.Equal(t, slug, resp.User.Username)
	require.Nil(t, resp.Org)
	require.False(t, resp.Claimable.User)
	require.False(t, resp.Claimable.Org)
}

func routeCleanupPG(t *testing.T) *pgxpool.Pool {
	t.Helper()
	dsn := os.Getenv("AUTHKIT_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("AUTHKIT_TEST_DATABASE_URL not set; skipping DB-backed test")
	}
	pool, err := pgxpool.New(context.Background(), dsn)
	require.NoError(t, err)
	t.Cleanup(pool.Close)
	return pool
}
