package authhttp

import (
	"context"
	"crypto/rsa"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	core "github.com/open-rails/authkit/core"
	jwtkit "github.com/open-rails/authkit/jwt"
	"github.com/stretchr/testify/require"
)

func newTestCoreService(t *testing.T) *core.Service {
	t.Helper()
	signer, err := jwtkit.NewRSASigner(2048, "test-kid")
	require.NoError(t, err)
	ks := core.Keyset{Active: signer, PublicKeys: map[string]*rsa.PublicKey{"test-kid": signer.PublicKey()}}
	opts := core.Options{
		Issuer:              "https://example.com",
		IssuedAudiences:     []string{"test-app"},
		ExpectedAudiences:   []string{"test-app"},
		AccessTokenDuration: time.Hour,
	}
	return core.NewService(opts, ks)
}

func TestJWKSHandler(t *testing.T) {
	svc := newTestCoreService(t)
	h := JWKSHandler(svc)

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/.well-known/jwks.json", nil)
	h.ServeHTTP(w, r)
	require.Equal(t, http.StatusOK, w.Code)

	var body map[string]any
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &body))
	_, ok := body["keys"]
	require.True(t, ok)
}

func TestAPIHandler_Token_InvalidRequest(t *testing.T) {
	s := &Service{svc: newTestCoreService(t)}
	h := s.APIHandler()

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/auth/token", strings.NewReader(`{}`))
	h.ServeHTTP(w, r)
	require.Equal(t, http.StatusBadRequest, w.Code)
	require.Contains(t, w.Body.String(), `"error":"invalid_request"`)
}

func TestAPIHandler_Logout_MissingSidClaim(t *testing.T) {
	s := &Service{svc: newTestCoreService(t)}
	h := s.APIHandler()

	tok, _, err := s.svc.IssueAccessToken(context.Background(), "user", "e@example.com", map[string]any{})
	require.NoError(t, err)

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodDelete, "/auth/logout", nil)
	r.Header.Set("Authorization", "Bearer "+tok)
	h.ServeHTTP(w, r)
	require.Equal(t, http.StatusBadRequest, w.Code)
	require.Contains(t, w.Body.String(), `"error":"missing_sid_claim"`)
}

func TestOIDCHandler_Callback_MissingStateOrCode(t *testing.T) {
	s := &Service{svc: newTestCoreService(t)}
	h := s.OIDCHandler()

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/auth/oidc/google/callback", nil)
	h.ServeHTTP(w, r)
	require.Equal(t, http.StatusBadRequest, w.Code)
	require.Contains(t, w.Body.String(), `"error":"invalid_request"`)
}

func TestAPIHandler_SolanaChallenge_InvalidRequest(t *testing.T) {
	s := &Service{svc: newTestCoreService(t)}
	h := s.APIHandler()

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/auth/solana/challenge", strings.NewReader(`{}`))
	r.Header.Set("Content-Type", "application/json")
	h.ServeHTTP(w, r)
	require.Equal(t, http.StatusBadRequest, w.Code)
	require.Contains(t, w.Body.String(), `"error":"address_required"`)
}

func TestAPIHandler_UserBootstrap_RequiresAuth(t *testing.T) {
	s := &Service{svc: newTestCoreService(t)}
	h := s.APIHandler()

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/auth/user/bootstrap", nil)
	h.ServeHTTP(w, r)
	require.Equal(t, http.StatusUnauthorized, w.Code)
	require.Contains(t, w.Body.String(), `"error":"missing_token"`)
}
