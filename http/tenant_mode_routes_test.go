package authhttp

import (
	"bytes"
	"context"
	"crypto"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	core "github.com/open-rails/authkit/core"
	jwtkit "github.com/open-rails/authkit/jwt"
	"github.com/stretchr/testify/require"
)

func newTestCoreServiceWithTenantMode(t *testing.T, mode string) *core.Service {
	t.Helper()
	signer, err := jwtkit.NewRSASigner(2048, "test-kid")
	require.NoError(t, err)
	ks := core.Keyset{Active: signer, PublicKeys: map[string]crypto.PublicKey{"test-kid": signer.PublicKey()}}
	opts := core.Options{
		Issuer:                   "https://example.com",
		IssuedAudiences:          []string{"test-app"},
		ExpectedAudiences:        []string{"test-app"},
		AccessTokenDuration:      time.Hour,
		RegistrationVerification: core.RegistrationVerificationNone,
	}
	return core.NewService(opts, ks)
}

func newTestServiceWithTenantMode(t *testing.T, mode string) *Service {
	t.Helper()
	coreSvc := newTestCoreServiceWithTenantMode(t, mode)
	opts := coreSvc.Options()
	ver := NewVerifier(WithSkew(5*time.Second), WithTenantMode(mode))
	_ = ver.AddIssuer(opts.Issuer, opts.ExpectedAudiences, IssuerOptions{
		RawKeys: coreSvc.PublicKeysByKID(),
	})
	ver.WithService(coreSvc)
	return &Service{svc: coreSvc, verifier: ver}
}

// (issue 60) Tenant routes are always registered (no tenant-mode gate); the host
// controls exposure by mounting the RouteTenants group. They require auth.
func TestAPIHandler_TokenTenant_RouteAlwaysRegistered(t *testing.T) {
	s := newTestServiceWithTenantMode(t, "")
	h := s.APIHandler()
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/token/tenant", bytes.NewReader([]byte(`{"tenant":"acme"}`)))
	h.ServeHTTP(w, r)
	require.Equal(t, http.StatusUnauthorized, w.Code)
	require.Contains(t, w.Body.String(), `"error":"missing_token"`)
}

func TestAPIHandler_TenantInviteRoutes_AlwaysRegistered(t *testing.T) {
	s := newTestServiceWithTenantMode(t, "")
	h := s.APIHandler()
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/me/invites", nil)
	h.ServeHTTP(w, r)
	require.Equal(t, http.StatusUnauthorized, w.Code)
	require.Contains(t, w.Body.String(), `"error":"missing_token"`)
}

func TestAPIHandler_TokenTenant_InvalidRequest(t *testing.T) {
	s := newTestServiceWithTenantMode(t, "multi")
	h := s.APIHandler()

	tok, _, err := s.svc.IssueAccessToken(context.Background(), "user", "e@example.com", map[string]any{})
	require.NoError(t, err)

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/token/tenant", bytes.NewReader([]byte(`{}`)))
	r.Header.Set("Authorization", "Bearer "+tok)
	r.Header.Set("Content-Type", "application/json")
	h.ServeHTTP(w, r)
	require.Equal(t, http.StatusBadRequest, w.Code)
	require.Contains(t, w.Body.String(), `"error":"invalid_request"`)
}
