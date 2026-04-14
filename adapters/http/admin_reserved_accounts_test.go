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

func TestHandleAdminOrgParkPOST_InvalidRequest(t *testing.T) {
	t.Parallel()

	s := &Service{svc: newTestCoreService(t)}
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/auth/admin/org/park", strings.NewReader(`{}`))
	r.Header.Set("Content-Type", "application/json")

	s.handleAdminOrgParkPOST(w, r)
	require.Equal(t, http.StatusBadRequest, w.Code)
	require.Contains(t, w.Body.String(), `"error":"invalid_request"`)
}

func TestHandleAdminOrgClaimPOST_InvalidRequest(t *testing.T) {
	t.Parallel()

	s := &Service{svc: newTestCoreService(t)}
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/auth/admin/org/claim", strings.NewReader(`{}`))
	r.Header.Set("Content-Type", "application/json")

	s.handleAdminOrgClaimPOST(w, r)
	require.Equal(t, http.StatusBadRequest, w.Code)
	require.Contains(t, w.Body.String(), `"error":"invalid_request"`)
}

func TestHandleAdminOrgClaimPOST_RequiresOwnerUserID(t *testing.T) {
	t.Parallel()

	s := &Service{svc: newTestCoreService(t)}
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/auth/admin/org/claim", strings.NewReader(`{"slug":"google"}`))
	r.Header.Set("Content-Type", "application/json")

	s.handleAdminOrgClaimPOST(w, r)
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
