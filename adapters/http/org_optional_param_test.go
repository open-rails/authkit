package authhttp

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	core "github.com/open-rails/authkit/core"
)

func TestPasswordLogin_OrgParamRejectedInSingleMode(t *testing.T) {
	cfg := core.Config{
		Issuer:            "https://example.com",
		IssuedAudiences:   []string{"test-app"},
		ExpectedAudiences: []string{"test-app"},
		BaseURL:           "https://example.com",
		OrgMode:           "single",
	}
	svc, err := NewService(cfg)
	require.NoError(t, err)

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/auth/password/login", strings.NewReader(`{"login":"x","password":"y","org":"acme"}`))
	r.Header.Set("Content-Type", "application/json")
	svc.APIHandler().ServeHTTP(w, r)
	require.Equal(t, http.StatusBadRequest, w.Code)
	require.JSONEq(t, `{"error":"org_not_supported"}`, w.Body.String())
}

func TestAuthToken_OrgParamRejectedInSingleMode(t *testing.T) {
	cfg := core.Config{
		Issuer:            "https://example.com",
		IssuedAudiences:   []string{"test-app"},
		ExpectedAudiences: []string{"test-app"},
		BaseURL:           "https://example.com",
		OrgMode:           "single",
	}
	svc, err := NewService(cfg)
	require.NoError(t, err)

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/auth/token", strings.NewReader(`{"grant_type":"refresh_token","refresh_token":"x","org":"acme"}`))
	r.Header.Set("Content-Type", "application/json")
	svc.APIHandler().ServeHTTP(w, r)
	require.Equal(t, http.StatusBadRequest, w.Code)
	require.JSONEq(t, `{"error":"org_not_supported"}`, w.Body.String())
}
