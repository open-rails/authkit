package authhttp

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	core "github.com/open-rails/authkit/core"
)

// (issue 60) The legacy "tenant_not_supported" rejection is gone — tenants are
// always a supported primitive, so a `tenant` param is accepted on every
// deployment. These assert the param is no longer rejected up front; downstream
// it follows normal auth/membership handling.

func TestPasswordLogin_TenantParamAccepted(t *testing.T) {
	cfg := core.Config{
		Issuer:                   "https://example.com",
		IssuedAudiences:          []string{"test-app"},
		ExpectedAudiences:        []string{"test-app"},
		BaseURL:                  "https://example.com",
		RegistrationVerification: core.RegistrationVerificationNone,
	}
	svc, err := NewService(cfg)
	require.NoError(t, err)

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/password/login", strings.NewReader(`{"login":"x","password":"y","tenant":"acme"}`))
	r.Header.Set("Content-Type", "application/json")
	svc.APIHandler().ServeHTTP(w, r)
	require.NotContains(t, w.Body.String(), "tenant_not_supported")
}

func TestAuthToken_TenantParamAccepted(t *testing.T) {
	cfg := core.Config{
		Issuer:                   "https://example.com",
		IssuedAudiences:          []string{"test-app"},
		ExpectedAudiences:        []string{"test-app"},
		BaseURL:                  "https://example.com",
		RegistrationVerification: core.RegistrationVerificationNone,
	}
	svc, err := NewService(cfg)
	require.NoError(t, err)

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/token", strings.NewReader(`{"grant_type":"refresh_token","refresh_token":"x","tenant":"acme"}`))
	r.Header.Set("Content-Type", "application/json")
	svc.APIHandler().ServeHTTP(w, r)
	require.NotContains(t, w.Body.String(), "tenant_not_supported")
}
