package authhttp

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestErrorShape_TokenInvalidRequest(t *testing.T) {
	s := &Service{svc: newTestCoreService(t)}
	h := s.APIHandler()

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/auth/token", strings.NewReader(`{}`))
	r.Header.Set("Content-Type", "application/json")
	h.ServeHTTP(w, r)

	require.Equal(t, http.StatusBadRequest, w.Code)
	require.Equal(t, "application/json", strings.TrimSpace(strings.Split(w.Header().Get("Content-Type"), ";")[0]))
	require.JSONEq(t, `{"error":"invalid_request"}`, w.Body.String())
}

func TestErrorShape_PasswordLoginInvalidRequest(t *testing.T) {
	s := &Service{svc: newTestCoreService(t)}
	h := s.APIHandler()

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/auth/password/login", strings.NewReader(`{}`))
	r.Header.Set("Content-Type", "application/json")
	h.ServeHTTP(w, r)

	require.Equal(t, http.StatusBadRequest, w.Code)
	require.JSONEq(t, `{"error":"invalid_request"}`, w.Body.String())
}

func TestErrorShape_RegisterInvalidRequest(t *testing.T) {
	s := &Service{svc: newTestCoreService(t)}
	h := s.APIHandler()

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/auth/register", strings.NewReader(`{}`))
	r.Header.Set("Content-Type", "application/json")
	h.ServeHTTP(w, r)

	require.Equal(t, http.StatusBadRequest, w.Code)
	require.JSONEq(t, `{"error":"invalid_request"}`, w.Body.String())
}

func TestErrorShape_LogoutMissingSidClaim(t *testing.T) {
	s := &Service{svc: newTestCoreService(t)}
	h := s.APIHandler()

	tok, _, err := s.svc.IssueAccessToken(context.Background(), "user", "e@example.com", map[string]any{})
	require.NoError(t, err)

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodDelete, "/auth/logout", nil)
	r.Header.Set("Authorization", "Bearer "+tok)
	h.ServeHTTP(w, r)

	require.Equal(t, http.StatusBadRequest, w.Code)
	require.JSONEq(t, `{"error":"missing_sid_claim"}`, w.Body.String())
}
