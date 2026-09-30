package httpapi

import (
	"net/http"
	"strings"

	"github.com/open-rails/authkit/internal/authflow"
	"github.com/open-rails/authkit/internal/contact"
	"github.com/open-rails/authkit/internal/errmodel"
)

func (s *Service) handleRegisterAvailabilityGET(w http.ResponseWriter, r *http.Request) {
	var q AvailabilityQuery
	if !readQuery(w, r, &q) {
		return
	}
	username, email, phone := q.Username, q.Email, q.PhoneNumber
	if username == "" && email == "" && phone == "" {
		fail(w, errmodel.CodeInvalidRequest)
		return
	}

	// When public registration is disabled, never report a name or email as
	// usable: every requested field is unavailable with a stable reason.
	if s.publicRegistrationDisabled() {
		resp := Availability{}
		if username != "" {
			resp.Username = unavailable(errmodel.CodeRegistrationDisabled.String())
		}
		if email != "" {
			resp.Email = unavailable(errmodel.CodeRegistrationDisabled.String())
		}
		if phone != "" {
			resp.PhoneNumber = unavailable(errmodel.CodeRegistrationDisabled.String())
		}
		writeJSON(w, http.StatusOK, resp)
		return
	}

	resp := Availability{}

	// Username and email conflicts are answered by ONE combined query:
	// CheckPendingRegistrationConflict → UserEmailOrUsernameTaken returns BOTH
	// email_taken and username_taken, so checking them together runs it once
	// instead of twice (#229). Each field is validated first; a field that fails
	// validation reports its validation error and is excluded from the check, so
	// the single call only covers the identifiers actually provided-and-valid.
	var checkEmail, checkUsername string
	var emailNeedsConflictCheck, usernameNeedsConflictCheck bool

	if username != "" {
		if _, err := s.svc.ValidateUsernameForRegistration(r.Context(), username); err != nil {
			code := authflow.ValidationErrorCode(err)
			if code == "" {
				// Not a validation error — an internal failure.
				s.logInternalError(r, "register_availability", "username", "database_error", err)
				serverErr(w, "database_error", nil)
				return
			}
			resp.Username = unavailable(code.String())
		} else {
			checkUsername = strings.TrimSpace(username)
			usernameNeedsConflictCheck = true
		}
	}
	if email != "" {
		if err := contact.ValidateEmail(email); err != nil {
			resp.Email = unavailable(authflow.ValidationErrorCode(err).String())
		} else {
			checkEmail = contact.NormalizeEmail(email)
			emailNeedsConflictCheck = true
		}
	}

	if emailNeedsConflictCheck || usernameNeedsConflictCheck {
		emailTaken, usernameTaken, err := s.svc.CheckPendingRegistrationConflict(r.Context(), checkEmail, checkUsername)
		if err != nil {
			s.logInternalError(r, "register_availability", "identifier", "database_error", err)
			serverErr(w, "database_error", nil)
			return
		}
		if usernameNeedsConflictCheck {
			if usernameTaken {
				resp.Username = unavailable("username_in_use")
			} else {
				resp.Username = &AvailabilityField{Available: true}
			}
		}
		if emailNeedsConflictCheck {
			if emailTaken {
				resp.Email = unavailable("email_in_use")
			} else {
				resp.Email = &AvailabilityField{Available: true}
			}
		}
	}

	if phone != "" {
		field, err := s.registrationPhoneAvailability(r, phone)
		if err != nil {
			s.logInternalError(r, "register_availability", "phone_number", "database_error", err)
			serverErr(w, "database_error", nil)
			return
		}
		resp.PhoneNumber = field
	}

	writeJSON(w, http.StatusOK, resp)
}

func (s *Service) registrationPhoneAvailability(r *http.Request, phone string) (*AvailabilityField, error) {
	if err := contact.ValidatePhone(phone); err != nil {
		return unavailable(authflow.ValidationErrorCode(err).String()), nil
	}
	phone = contact.NormalizePhone(phone)

	phoneTaken, _, err := s.svc.CheckPhoneRegistrationConflict(r.Context(), phone, "")
	if err != nil {
		return nil, err
	}
	if phoneTaken {
		return unavailable("phone_in_use"), nil
	}

	return &AvailabilityField{Available: true}, nil
}

func unavailable(code string) *AvailabilityField {
	return &AvailabilityField{Error: &code}
}
