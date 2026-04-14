package authhttp

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestHandleOwnerNamespaceInfoGET_InvalidRequest(t *testing.T) {
	t.Parallel()

	s := &Service{svc: newTestCoreService(t)}
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/auth/owners/", nil)

	s.handleOwnerNamespaceInfoGET(w, r)
	require.Equal(t, http.StatusBadRequest, w.Code)
	require.Contains(t, w.Body.String(), `"error":"invalid_request"`)
}

func TestHandleAdminAccountParkPOST_InvalidRequest(t *testing.T) {
	t.Parallel()

	s := &Service{svc: newTestCoreService(t)}
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/auth/admin/account/park", strings.NewReader(`{}`))
	r.Header.Set("Content-Type", "application/json")

	s.handleAdminAccountParkPOST(w, r)
	require.Equal(t, http.StatusBadRequest, w.Code)
	require.Contains(t, w.Body.String(), `"error":"invalid_request"`)
}

func TestHandleAdminAccountClaimPOST_InvalidRequest(t *testing.T) {
	t.Parallel()

	s := &Service{svc: newTestCoreService(t)}
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/auth/admin/account/claim", strings.NewReader(`{}`))
	r.Header.Set("Content-Type", "application/json")

	s.handleAdminAccountClaimPOST(w, r)
	require.Equal(t, http.StatusBadRequest, w.Code)
	require.Contains(t, w.Body.String(), `"error":"invalid_request"`)
}

func TestHandleAdminAccountClaimPOST_RequiresOwnerUserIDForOrgKind(t *testing.T) {
	t.Parallel()

	s := &Service{svc: newTestCoreService(t)}
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/auth/admin/account/claim", strings.NewReader(`{"kind":"org","slug":"google"}`))
	r.Header.Set("Content-Type", "application/json")

	s.handleAdminAccountClaimPOST(w, r)
	require.Equal(t, http.StatusBadRequest, w.Code)
	require.Contains(t, w.Body.String(), `"error":"invalid_request"`)
}

func TestHandleAdminAccountParkPOST_RejectsUnknownKind(t *testing.T) {
	t.Parallel()

	s := &Service{svc: newTestCoreService(t)}
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/auth/admin/account/park", strings.NewReader(`{"kind":"team","slug":"google"}`))
	r.Header.Set("Content-Type", "application/json")

	s.handleAdminAccountParkPOST(w, r)
	require.Equal(t, http.StatusBadRequest, w.Code)
	require.Contains(t, w.Body.String(), `"error":"invalid_request"`)
}

func TestHandleAdminAccountsRestrictPOST_InvalidRequest(t *testing.T) {
	t.Parallel()

	s := &Service{svc: newTestCoreService(t)}
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/auth/admin/accounts/restrict", strings.NewReader(`{}`))
	r.Header.Set("Content-Type", "application/json")

	s.handleAdminAccountsRestrictPOST(w, r)
	require.Equal(t, http.StatusBadRequest, w.Code)
	require.Contains(t, w.Body.String(), `"error":"invalid_request"`)
}

func TestHandleAdminAccountsRestrictPOST_RequiresNonEmptySlugs(t *testing.T) {
	t.Parallel()

	s := &Service{svc: newTestCoreService(t)}
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/auth/admin/accounts/restrict", strings.NewReader(`{"slugs":[]}`))
	r.Header.Set("Content-Type", "application/json")

	s.handleAdminAccountsRestrictPOST(w, r)
	require.Equal(t, http.StatusBadRequest, w.Code)
	require.Contains(t, w.Body.String(), `"error":"invalid_request"`)
}

func TestHandleAdminAccountsUnrestrictPOST_InvalidRequest(t *testing.T) {
	t.Parallel()

	s := &Service{svc: newTestCoreService(t)}
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/auth/admin/accounts/unrestrict", strings.NewReader(`{}`))
	r.Header.Set("Content-Type", "application/json")

	s.handleAdminAccountsUnrestrictPOST(w, r)
	require.Equal(t, http.StatusBadRequest, w.Code)
	require.Contains(t, w.Body.String(), `"error":"invalid_request"`)
}

func TestHandleAdminAccountsUnrestrictPOST_RequiresNonEmptySlugs(t *testing.T) {
	t.Parallel()

	s := &Service{svc: newTestCoreService(t)}
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/auth/admin/accounts/unrestrict", strings.NewReader(`{"slugs":[]}`))
	r.Header.Set("Content-Type", "application/json")

	s.handleAdminAccountsUnrestrictPOST(w, r)
	require.Equal(t, http.StatusBadRequest, w.Code)
	require.Contains(t, w.Body.String(), `"error":"invalid_request"`)
}
