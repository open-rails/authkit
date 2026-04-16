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

func newTestService(t *testing.T) *Service {
	t.Helper()
	coreSvc := newTestCoreService(t)
	opts := coreSvc.Options()
	ver := NewVerifier(WithSkew(5 * time.Second))
	_ = ver.AddIssuer(opts.Issuer, opts.ExpectedAudiences, IssuerOptions{
		RawKeys: coreSvc.PublicKeysByKID(),
	})
	ver.WithService(coreSvc)
	return &Service{svc: coreSvc, verifier: ver}
}

func TestJWKSHandler(t *testing.T) {
	svc := newTestCoreService(t)
	h := JWKSHandler(svc.JWKS())

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/.well-known/jwks.json", nil)
	h.ServeHTTP(w, r)
	require.Equal(t, http.StatusOK, w.Code)

	var body struct {
		Keys []struct {
			Kty string `json:"kty"`
			Kid string `json:"kid"`
			Alg string `json:"alg"`
		} `json:"keys"`
	}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &body))
	require.NotEmpty(t, body.Keys)
	require.Equal(t, "RSA", body.Keys[0].Kty)
	require.NotEmpty(t, body.Keys[0].Kid)
	require.Equal(t, "RS256", body.Keys[0].Alg)
}

func TestAPIHandler_Token_InvalidRequest(t *testing.T) {
	s := newTestService(t)
	h := s.APIHandler()

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/auth/token", strings.NewReader(`{}`))
	h.ServeHTTP(w, r)
	require.Equal(t, http.StatusBadRequest, w.Code)
	require.Contains(t, w.Body.String(), `"error":"invalid_request"`)
}

func TestAPIHandler_Logout_MissingSidClaim(t *testing.T) {
	s := newTestService(t)
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
	s := newTestService(t)
	h := s.OIDCHandler()

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/oidc/google/callback", nil)
	h.ServeHTTP(w, r)
	require.Equal(t, http.StatusBadRequest, w.Code)
	require.Contains(t, w.Body.String(), `"error":"invalid_request"`)
}

func TestOIDCHandler_LegacyAuthPathNotMounted(t *testing.T) {
	s := newTestService(t)
	h := s.OIDCHandler()

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/auth/oidc/google/callback", nil)
	h.ServeHTTP(w, r)
	require.Equal(t, http.StatusNotFound, w.Code)
}

func TestAPIHandler_SolanaChallenge_InvalidRequest(t *testing.T) {
	s := newTestService(t)
	h := s.APIHandler()

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/auth/solana/challenge", strings.NewReader(`{}`))
	r.Header.Set("Content-Type", "application/json")
	h.ServeHTTP(w, r)
	require.Equal(t, http.StatusBadRequest, w.Code)
	require.Contains(t, w.Body.String(), `"error":"address_required"`)
}

func TestAPIHandler_UserBootstrap_RequiresAuth(t *testing.T) {
	s := newTestService(t)
	h := s.APIHandler()

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/auth/user/bootstrap", nil)
	h.ServeHTTP(w, r)
	require.Equal(t, http.StatusUnauthorized, w.Code)
	require.Contains(t, w.Body.String(), `"error":"missing_token"`)
}

func TestAPIHandler_PublicOwnerNamespaceLookup_DoesNotRequireAuth(t *testing.T) {
	s := newTestService(t)
	h := s.APIHandler()

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/auth/owners/%20", nil)
	h.ServeHTTP(w, r)
	require.Equal(t, http.StatusBadRequest, w.Code)
	require.Contains(t, w.Body.String(), `"error":"invalid_request"`)
}

func TestAPIHandler_PublicOwnerNamespaceStateRoute_Removed(t *testing.T) {
	s := newTestService(t)
	h := s.APIHandler()

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/auth/orgs/state?slug=google", nil)
	h.ServeHTTP(w, r)
	require.Equal(t, http.StatusNotFound, w.Code)
}

func TestAPIHandler_AdminAccountsStateRoute_Removed(t *testing.T) {
	s := newTestService(t)
	h := s.APIHandler()

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/auth/admin/accounts/state?slug=google", nil)
	h.ServeHTTP(w, r)
	require.Equal(t, http.StatusNotFound, w.Code)
}

func TestAPIHandler_AdminAccountsReserveRoute_Removed(t *testing.T) {
	s := newTestService(t)
	h := s.APIHandler()

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/auth/admin/accounts/reserve", strings.NewReader(`{"slug":"google"}`))
	r.Header.Set("Content-Type", "application/json")
	h.ServeHTTP(w, r)
	require.Equal(t, http.StatusNotFound, w.Code)
}

func TestAPIHandler_AdminUsersToggleActiveRoute_Removed(t *testing.T) {
	s := newTestService(t)
	h := s.APIHandler()

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/auth/admin/users/toggle-active", strings.NewReader(`{"user_id":"u","banned":true}`))
	r.Header.Set("Content-Type", "application/json")
	h.ServeHTTP(w, r)
	require.Equal(t, http.StatusNotFound, w.Code)
}

func TestAPIHandler_AdminAccountParkRoute_RequiresAuth(t *testing.T) {
	s := newTestService(t)
	h := s.APIHandler()

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/auth/admin/account/park", strings.NewReader(`{"kind":"org","slug":"google"}`))
	r.Header.Set("Content-Type", "application/json")
	h.ServeHTTP(w, r)
	require.Equal(t, http.StatusUnauthorized, w.Code)
	require.Contains(t, w.Body.String(), `"error":"missing_token"`)
}

func TestAPIHandler_AdminAccountClaimRoute_RequiresAuth(t *testing.T) {
	s := newTestService(t)
	h := s.APIHandler()

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/auth/admin/account/claim", strings.NewReader(`{"kind":"org","slug":"google","owner_user_id":"abc"}`))
	r.Header.Set("Content-Type", "application/json")
	h.ServeHTTP(w, r)
	require.Equal(t, http.StatusUnauthorized, w.Code)
	require.Contains(t, w.Body.String(), `"error":"missing_token"`)
}

func TestAPIHandler_AdminOrgParkClaimLegacyRoutes_Removed(t *testing.T) {
	s := newTestService(t)
	h := s.APIHandler()

	w1 := httptest.NewRecorder()
	r1 := httptest.NewRequest(http.MethodPost, "/auth/admin/org/park", strings.NewReader(`{"slug":"google"}`))
	r1.Header.Set("Content-Type", "application/json")
	h.ServeHTTP(w1, r1)
	require.Equal(t, http.StatusNotFound, w1.Code)

	w2 := httptest.NewRecorder()
	r2 := httptest.NewRequest(http.MethodPost, "/auth/admin/org/claim", strings.NewReader(`{"slug":"google","owner_user_id":"abc"}`))
	r2.Header.Set("Content-Type", "application/json")
	h.ServeHTTP(w2, r2)
	require.Equal(t, http.StatusNotFound, w2.Code)
}

func TestAPIHandler_AdminAccountsOrgLegacyRoutes_Removed(t *testing.T) {
	s := newTestService(t)
	h := s.APIHandler()

	w1 := httptest.NewRecorder()
	r1 := httptest.NewRequest(http.MethodPost, "/auth/admin/accounts/park", strings.NewReader(`{"slug":"google"}`))
	r1.Header.Set("Content-Type", "application/json")
	h.ServeHTTP(w1, r1)
	require.Equal(t, http.StatusNotFound, w1.Code)

	w2 := httptest.NewRecorder()
	r2 := httptest.NewRequest(http.MethodPost, "/auth/admin/accounts/claim-org", strings.NewReader(`{"slug":"google","owner_user_id":"abc"}`))
	r2.Header.Set("Content-Type", "application/json")
	h.ServeHTTP(w2, r2)
	require.Equal(t, http.StatusNotFound, w2.Code)
}
