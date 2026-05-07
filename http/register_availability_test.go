package authhttp

import (
	"net/http"
	"net/http/httptest"
	"testing"

	core "github.com/open-rails/authkit/core"
	"github.com/stretchr/testify/require"
)

func TestRegisterAvailability_MissingFields(t *testing.T) {
	s := newTestService(t)
	h := s.APIHandler()

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/register/availability", nil)
	h.ServeHTTP(w, r)

	require.Equal(t, http.StatusBadRequest, w.Code)
	require.JSONEq(t, `{"error":"invalid_request"}`, w.Body.String())
}

func TestRegisterAvailability_InvalidUsernameDoesNotRequireDatabase(t *testing.T) {
	s := newTestService(t)
	h := s.APIHandler()

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/register/availability?username=1bad", nil)
	h.ServeHTTP(w, r)

	require.Equal(t, http.StatusOK, w.Code)
	require.JSONEq(t, `{"username":{"available":false,"error":"username_must_start_with_letter"}}`, w.Body.String())
}

func TestRegistrationUsernameUnavailableError(t *testing.T) {
	require.Equal(t, "username_not_allowed", registrationUsernameUnavailableError(core.OwnerNamespaceStatusRestrictedName))
	require.Equal(t, "username_not_allowed", registrationUsernameUnavailableError(core.OwnerNamespaceStatusParkedUser))
	require.Equal(t, "username_in_use", registrationUsernameUnavailableError(core.OwnerNamespaceStatusRegisteredUser))
	require.Equal(t, "username_in_use", registrationUsernameUnavailableError(core.OwnerNamespaceStatusHeldByRecentUserRename))
}
