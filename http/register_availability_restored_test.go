package authhttp

import (
	"net/http"
	"net/http/httptest"
	"testing"

	core "github.com/open-rails/authkit/core"
	"github.com/stretchr/testify/require"
)

// Restores coverage from the deleted register_availability_test.go after the
// org→permission-group hard cut (#111). The disabled-mode case uses the local
// newRegistrationModeService helper (only NativeUserRegistrationMode survives;
// OrgRegistrationMode was removed). The no-DB validation cases use newTestService.

func TestRestoredRegisterAvailability_MissingFields(t *testing.T) {
	s := newTestService(t)
	h := s.APIHandler()

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/register/availability", nil)
	h.ServeHTTP(w, r)

	require.Equal(t, http.StatusBadRequest, w.Code)
	requireErrorCode(t, w.Body.String(), "invalid_request")
}

func TestRestoredRegisterAvailability_InvalidUsernameDoesNotRequireDatabase(t *testing.T) {
	s := newTestService(t)
	h := s.APIHandler()

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/register/availability?username=1bad", nil)
	h.ServeHTTP(w, r)

	require.Equal(t, http.StatusOK, w.Code)
	require.JSONEq(t, `{"username":{"available":false,"error":"username_must_start_with_letter"}}`, w.Body.String())
}

func TestRestoredRegisterAvailability_InvalidPhoneDoesNotRequireDatabase(t *testing.T) {
	s := newTestService(t)
	h := s.APIHandler()

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/register/availability?phone_number=5551234", nil)
	h.ServeHTTP(w, r)

	require.Equal(t, http.StatusOK, w.Code)
	require.JSONEq(t, `{"phone_number":{"available":false,"error":"invalid_phone_number"}}`, w.Body.String())
}

// When native-user registration is disabled, availability reports every
// requested field (username/email/phone) as unavailable with a stable reason —
// no DB lookup happens.
func TestRestoredRegisterAvailability_DisabledIncludesAllFields(t *testing.T) {
	s := newRegistrationModeService(t, core.RegistrationModeAdminBootstrapOnly)
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

// When native-user registration is disabled, the public /register POST is
// short-circuited with registration_disabled before any body parsing or DB use.
func TestRestoredRegisterPost_DisabledShortCircuits(t *testing.T) {
	s := newRegistrationModeService(t, core.RegistrationModeAdminBootstrapOnly)
	h := s.APIHandler()

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/register", nil)
	r.Header.Set("Content-Type", "application/json")
	h.ServeHTTP(w, r)

	require.Contains(t, w.Body.String(), "registration_disabled")
}

// With the default (open) registration mode, /register is NOT short-circuited:
// the policy gate must not fire (it fails later for other reasons, but never
// with registration_disabled).
func TestRestoredRegisterPost_OpenNotShortCircuited(t *testing.T) {
	s := newTestService(t)
	require.True(t, s.svc.Options().PublicNativeUserRegistrationEnabled())

	h := s.APIHandler()
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/register", nil)
	r.Header.Set("Content-Type", "application/json")
	h.ServeHTTP(w, r)

	require.NotContains(t, w.Body.String(), "registration_disabled")
}
