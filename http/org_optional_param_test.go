package authhttp

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	core "github.com/open-rails/authkit/core"
)

func TestPasswordLogin_OrgParamRejected(t *testing.T) {
	cfg := core.Config{
		Token: core.TokenConfig{
			Issuer:            "https://example.com",
			IssuedAudiences:   []string{"test-app"},
			ExpectedAudiences: []string{"test-app"},
		},
		Frontend:     core.FrontendConfig{BaseURL: "https://example.com"},
		Registration: core.RegistrationConfig{Verification: core.RegistrationVerificationNone},
	}
	svc, err := NewServer(cfg, newNoDBPool(t))
	require.NoError(t, err)

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/password/login", strings.NewReader(`{"login":"x","password":"y","org":"acme"}`))
	r.Header.Set("Content-Type", "application/json")
	svc.APIHandler().ServeHTTP(w, r)
	require.Equal(t, http.StatusBadRequest, w.Code)
	require.Contains(t, w.Body.String(), `"code":"invalid_request"`)
}

func TestAuthToken_OrgParamRejected(t *testing.T) {
	cfg := core.Config{
		Token: core.TokenConfig{
			Issuer:            "https://example.com",
			IssuedAudiences:   []string{"test-app"},
			ExpectedAudiences: []string{"test-app"},
		},
		Frontend:     core.FrontendConfig{BaseURL: "https://example.com"},
		Registration: core.RegistrationConfig{Verification: core.RegistrationVerificationNone},
	}
	svc, err := NewServer(cfg, newNoDBPool(t))
	require.NoError(t, err)

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/token", strings.NewReader(`{"grant_type":"refresh_token","refresh_token":"x","org":"acme"}`))
	r.Header.Set("Content-Type", "application/json")
	svc.APIHandler().ServeHTTP(w, r)
	require.Equal(t, http.StatusBadRequest, w.Code)
	require.Contains(t, w.Body.String(), `"code":"invalid_request"`)
}
