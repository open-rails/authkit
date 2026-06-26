package authhttp

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/open-rails/authkit/embedded"
	"github.com/stretchr/testify/require"
)

func TestRegisterAvailability_MissingFields(t *testing.T) {
	s := newTestService(t)
	h := s.APIHandler()

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/register/availability", nil)
	h.ServeHTTP(w, r)

	require.Equal(t, http.StatusBadRequest, w.Code)
	requireErrorCode(t, w.Body.String(), "invalid_request")
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

// When native-user registration is disabled, availability reports every
// requested field (username/email/phone) as unavailable with a stable reason —
// no DB lookup happens.
func TestRegisterAvailability_DisabledIncludesAllFields(t *testing.T) {
	s := newRegistrationModeService(t, embedded.RegistrationModeClosed)
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

// When native-user registration is closed, the public /register POST is not mounted.
func TestRegisterPost_DisabledShortCircuits(t *testing.T) {
	s := newRegistrationModeService(t, embedded.RegistrationModeClosed)
	h := s.APIHandler()

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/register", nil)
	r.Header.Set("Content-Type", "application/json")
	h.ServeHTTP(w, r)

	require.Equal(t, http.StatusNotFound, w.Code)
}

// With the default (open) registration mode, /register is NOT short-circuited:
// the policy gate must not fire (it fails later for other reasons, but never
// with registration_disabled).
func TestRegisterPost_OpenNotShortCircuited(t *testing.T) {
	s := newTestService(t)
	require.True(t, s.svc.Options().PublicNativeUserRegistrationEnabled())

	h := s.APIHandler()
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/register", nil)
	r.Header.Set("Content-Type", "application/json")
	h.ServeHTTP(w, r)

	require.NotContains(t, w.Body.String(), "registration_disabled")
}
