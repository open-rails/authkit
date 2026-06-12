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

func TestRegisterAvailability_InvalidPhoneDoesNotRequireDatabase(t *testing.T) {
	s := newTestService(t)
	h := s.APIHandler()

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/register/availability?phone_number=5551234", nil)
	h.ServeHTTP(w, r)

	require.Equal(t, http.StatusOK, w.Code)
	require.JSONEq(t, `{"phone_number":{"available":false,"error":"invalid_phone_number"}}`, w.Body.String())
}

func TestRegisterAvailability_DisabledIncludesPhone(t *testing.T) {
	s := newTestServiceWithPolicy(t, core.RegistrationModeAdminBootstrapOnly, core.RegistrationModeOpen)
	h := s.APIHandler()

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/register/availability?username=alice&email=a@example.com&phone_number=%2B12025550123", nil)
	h.ServeHTTP(w, r)

	require.Equal(t, http.StatusOK, w.Code)
	require.JSONEq(t, `{
		"username":{"available":false,"error":"registration_disabled"},
		"email":{"available":false,"error":"registration_disabled"},
		"phone_number":{"available":false,"error":"registration_disabled"}
	}`, w.Body.String())
}
