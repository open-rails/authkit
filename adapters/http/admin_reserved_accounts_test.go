package authhttp

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestHandleAdminAccountsReservePOST_NoHardcodedReservedSlugBlock(t *testing.T) {
	t.Parallel()

	s := &Service{svc: newTestCoreService(t)}
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/auth/admin/accounts/reserve", strings.NewReader(`{"slug":"superuser"}`))
	r.Header.Set("Content-Type", "application/json")

	s.handleAdminAccountsReservePOST(w, r)
	require.Equal(t, http.StatusInternalServerError, w.Code)
	require.Contains(t, w.Body.String(), `"error":"account_reserve_failed"`)
	require.NotContains(t, w.Body.String(), `"error":"username_reserved"`)
}

func TestHandleAdminAccountsStateGET_InvalidRequest(t *testing.T) {
	t.Parallel()

	s := &Service{svc: newTestCoreService(t)}
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/auth/admin/accounts/state", nil)

	s.handleAdminAccountsStateGET(w, r)
	require.Equal(t, http.StatusBadRequest, w.Code)
	require.Contains(t, w.Body.String(), `"error":"invalid_request"`)
}

func TestHandleAdminAccountsParkPOST_InvalidRequest(t *testing.T) {
	t.Parallel()

	s := &Service{svc: newTestCoreService(t)}
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/auth/admin/accounts/park", strings.NewReader(`{}`))
	r.Header.Set("Content-Type", "application/json")

	s.handleAdminAccountsParkPOST(w, r)
	require.Equal(t, http.StatusBadRequest, w.Code)
	require.Contains(t, w.Body.String(), `"error":"invalid_request"`)
}

func TestHandleAdminAccountsClaimOrgPOST_InvalidRequest(t *testing.T) {
	t.Parallel()

	s := &Service{svc: newTestCoreService(t)}
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/auth/admin/accounts/claim-org", strings.NewReader(`{}`))
	r.Header.Set("Content-Type", "application/json")

	s.handleAdminAccountsClaimOrgPOST(w, r)
	require.Equal(t, http.StatusBadRequest, w.Code)
	require.Contains(t, w.Body.String(), `"error":"invalid_request"`)
}

func TestHandleAdminAccountsClaimOrgPOST_RequiresOwnerUserID(t *testing.T) {
	t.Parallel()

	s := &Service{svc: newTestCoreService(t)}
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/auth/admin/accounts/claim-org", strings.NewReader(`{"slug":"google"}`))
	r.Header.Set("Content-Type", "application/json")

	s.handleAdminAccountsClaimOrgPOST(w, r)
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
