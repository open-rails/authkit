package httpapi

import (
	"net/http"
	"strings"

	"github.com/open-rails/authkit/internal/authflow"
	"github.com/open-rails/authkit/internal/errmodel"
)

// handleRegisterAvailabilityGET answers for a username only. It never says
// whether an email address or phone number has an account (a sign-up with a
// taken one answers like a fresh one), so those parameters are ignored.
func (s *Service) handleRegisterAvailabilityGET(w http.ResponseWriter, r *http.Request) {
	var q AvailabilityQuery
	if !readQuery(w, r, &q) {
		return
	}
	username := q.Username
	if username == "" {
		fail(w, errmodel.CodeInvalidRequest)
		return
	}

	// When public registration is disabled, never report a name as usable.
	if s.publicRegistrationDisabled() {
		writeJSON(w, http.StatusOK, Availability{Username: unavailable(errmodel.CodeRegistrationDisabled.String())})
		return
	}

	resp := Availability{}
	if _, err := s.svc.ValidateUsernameForRegistration(r.Context(), username); err != nil {
		code := authflow.ValidationErrorCode(err)
		if code == "" {
			// Not a validation error — an internal failure.
			s.logInternalError(r, "register_availability", "username", "database_error", err)
			serverErr(w, "database_error", nil)
			return
		}
		resp.Username = unavailable(code.String())
		writeJSON(w, http.StatusOK, resp)
		return
	}
	// Covers pending registrations as well as accounts.
	_, usernameTaken, err := s.svc.CheckPendingRegistrationConflict(r.Context(), "", strings.TrimSpace(username))
	if err != nil {
		s.logInternalError(r, "register_availability", "username", "database_error", err)
		serverErr(w, "database_error", nil)
		return
	}
	if usernameTaken {
		resp.Username = unavailable("username_in_use")
	} else {
		resp.Username = &AvailabilityField{Available: true}
	}
	writeJSON(w, http.StatusOK, resp)
}

func unavailable(code string) *AvailabilityField {
	return &AvailabilityField{Error: &code}
}
