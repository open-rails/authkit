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

func TestHandleAdminAccountsClaimPOST_NoHardcodedReservedSlugBlock(t *testing.T) {
	t.Parallel()

	s := &Service{svc: newTestCoreService(t)}
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/auth/admin/accounts/claim", strings.NewReader(`{"slug":"superuser","password":"example-password"}`))
	r.Header.Set("Content-Type", "application/json")

	s.handleAdminAccountsClaimPOST(w, r)
	require.Equal(t, http.StatusBadRequest, w.Code)
	require.Contains(t, w.Body.String(), `"error":"account_claim_failed"`)
	require.NotContains(t, w.Body.String(), `"error":"username_reserved"`)
}
