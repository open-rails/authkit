package authhttp

import (
	"bytes"
	"context"
	"crypto/rsa"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	core "github.com/open-rails/authkit/core"
	jwtkit "github.com/open-rails/authkit/jwt"
	"github.com/stretchr/testify/require"
)

func newTestCoreServiceWithOrgMode(t *testing.T, mode string) *core.Service {
	t.Helper()
	signer, err := jwtkit.NewRSASigner(2048, "test-kid")
	require.NoError(t, err)
	ks := core.Keyset{Active: signer, PublicKeys: map[string]*rsa.PublicKey{"test-kid": signer.PublicKey()}}
	opts := core.Options{
		Issuer:              "https://example.com",
		IssuedAudiences:     []string{"test-app"},
		ExpectedAudiences:   []string{"test-app"},
		AccessTokenDuration: time.Hour,
		OrgMode:             mode,
	}
	return core.NewService(opts, ks)
}

func TestAPIHandler_TokenOrg_RouteOnlyInMultiMode(t *testing.T) {
	// single: route not registered
	sSingle := &Service{svc: newTestCoreServiceWithOrgMode(t, "single")}
	hSingle := sSingle.APIHandler()
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/auth/token/org", bytes.NewReader([]byte(`{"org":"acme"}`)))
	hSingle.ServeHTTP(w, r)
	require.Equal(t, http.StatusNotFound, w.Code)

	// multi: route registered and requires auth
	sMulti := &Service{svc: newTestCoreServiceWithOrgMode(t, "multi")}
	hMulti := sMulti.APIHandler()
	w2 := httptest.NewRecorder()
	r2 := httptest.NewRequest(http.MethodPost, "/auth/token/org", bytes.NewReader([]byte(`{"org":"acme"}`)))
	hMulti.ServeHTTP(w2, r2)
	require.Equal(t, http.StatusUnauthorized, w2.Code)
	require.Contains(t, w2.Body.String(), `"error":"missing_token"`)
}

func TestAPIHandler_OrgInviteRoutes_OnlyInMultiMode(t *testing.T) {
	// single: routes not registered
	sSingle := &Service{svc: newTestCoreServiceWithOrgMode(t, "single")}
	hSingle := sSingle.APIHandler()
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/auth/org-invites", nil)
	hSingle.ServeHTTP(w, r)
	require.Equal(t, http.StatusNotFound, w.Code)

	// multi: route registered and requires auth
	sMulti := &Service{svc: newTestCoreServiceWithOrgMode(t, "multi")}
	hMulti := sMulti.APIHandler()
	w2 := httptest.NewRecorder()
	r2 := httptest.NewRequest(http.MethodGet, "/auth/org-invites", nil)
	hMulti.ServeHTTP(w2, r2)
	require.Equal(t, http.StatusUnauthorized, w2.Code)
	require.Contains(t, w2.Body.String(), `"error":"missing_token"`)
}

func TestAPIHandler_TokenOrg_InvalidRequest(t *testing.T) {
	s := &Service{svc: newTestCoreServiceWithOrgMode(t, "multi")}
	h := s.APIHandler()

	tok, _, err := s.svc.IssueAccessToken(context.Background(), "user", "e@example.com", map[string]any{})
	require.NoError(t, err)

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/auth/token/org", bytes.NewReader([]byte(`{}`)))
	r.Header.Set("Authorization", "Bearer "+tok)
	r.Header.Set("Content-Type", "application/json")
	h.ServeHTTP(w, r)
	require.Equal(t, http.StatusBadRequest, w.Code)
	require.Contains(t, w.Body.String(), `"error":"invalid_request"`)
}
