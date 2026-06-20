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
		Issuer:                   "https://example.com",
		IssuedAudiences:          []string{"test-app"},
		ExpectedAudiences:        []string{"test-app"},
		BaseURL:                  "https://example.com",
		RegistrationVerification: core.RegistrationVerificationNone,
	}
	svc, err := NewService(cfg)
	require.NoError(t, err)
	sms := &captureSMSSender{}
	svc = svc.WithPostgres(pool).WithSMSSender(sms)

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

func TestNamespaceLookupReturnsSameSlugUserAndOrg(t *testing.T) {
	ctx := context.Background()
	pool := routeCleanupPG(t)
	const slug = "same-slug-96"
	_, _ = pool.Exec(ctx, `DELETE FROM profiles.orgs WHERE slug=$1`, slug)
	_, _ = pool.Exec(ctx, `DELETE FROM profiles.users WHERE username=$1`, slug)

	cfg := core.Config{
		Issuer:                   "https://example.com",
		IssuedAudiences:          []string{"test-app"},
		ExpectedAudiences:        []string{"test-app"},
		BaseURL:                  "https://example.com",
		RegistrationVerification: core.RegistrationVerificationNone,
	}
	svc, err := NewService(cfg)
	require.NoError(t, err)
	svc = svc.WithPostgres(pool)

	user, err := svc.svc.CreateUser(ctx, slug+"@example.com", slug)
	require.NoError(t, err)
	_, err = svc.svc.CreateOrgForUser(ctx, core.CreateOrgForUserRequest{Slug: slug, OwnerUserID: user.ID})
	require.NoError(t, err)
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
	require.NotNil(t, resp.Org)
	require.Equal(t, slug, resp.Org.Slug)
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
