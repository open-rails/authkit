package authhttp

import (
	"net/http"
	"strings"

	"github.com/open-rails/authkit/embedded"
)

type registrationAvailabilityField struct {
	Available bool   `json:"available"`
	Error     string `json:"error,omitempty"`
}

type registrationAvailabilityResponse struct {
	Username    *registrationAvailabilityField `json:"username,omitempty"`
	Email       *registrationAvailabilityField `json:"email,omitempty"`
	PhoneNumber *registrationAvailabilityField `json:"phone_number,omitempty"`
}

func (s *Service) handleRegisterAvailabilityGET(w http.ResponseWriter, r *http.Request) {
	if s.rateLimited(w, r, RLAuthRegisterAvailability) {
		return
	}

	username := strings.TrimSpace(r.URL.Query().Get("username"))
	email := strings.TrimSpace(r.URL.Query().Get("email"))
	phone := strings.TrimSpace(r.URL.Query().Get("phone_number"))
	if username == "" && email == "" && phone == "" {
		badRequest(w, ErrInvalidRequest)
		return
	}

	// When public registration is disabled, never report a name or email as
	// usable: every requested field is unavailable with a stable reason.
	if s.publicRegistrationDisabled() {
		resp := registrationAvailabilityResponse{}
		if username != "" {
			resp.Username = &registrationAvailabilityField{Available: false, Error: ErrRegistrationDisabled.String()}
		}
		if email != "" {
			resp.Email = &registrationAvailabilityField{Available: false, Error: ErrRegistrationDisabled.String()}
		}
		if phone != "" {
			resp.PhoneNumber = &registrationAvailabilityField{Available: false, Error: ErrRegistrationDisabled.String()}
		}
		writeJSON(w, http.StatusOK, resp)
		return
	}

	resp := registrationAvailabilityResponse{}

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
			code := ErrorCode(embedded.ValidationErrorCode(err))
			if code == "" {
				// Not a validation error — an internal failure.
				s.logInternalError(r, "register_availability", "username", "database_error", err)
				serverErr(w, ErrDatabaseError)
				return
			}
			resp.Username = &registrationAvailabilityField{Available: false, Error: code.String()}
		} else {
			checkUsername = strings.TrimSpace(username)
			usernameNeedsConflictCheck = true
		}
	}
	if email != "" {
		if err := embedded.ValidateEmail(email); err != nil {
			resp.Email = &registrationAvailabilityField{Available: false, Error: ErrorCode(embedded.ValidationErrorCode(err)).String()}
		} else {
			checkEmail = embedded.NormalizeEmail(email)
			emailNeedsConflictCheck = true
		}
	}

	if emailNeedsConflictCheck || usernameNeedsConflictCheck {
		emailTaken, usernameTaken, err := s.svc.CheckPendingRegistrationConflict(r.Context(), checkEmail, checkUsername)
		if err != nil {
			s.logInternalError(r, "register_availability", "identifier", "database_error", err)
			serverErr(w, ErrDatabaseError)
			return
		}
		if usernameNeedsConflictCheck {
			if usernameTaken {
				resp.Username = &registrationAvailabilityField{Available: false, Error: "username_in_use"}
			} else {
				resp.Username = &registrationAvailabilityField{Available: true}
			}
		}
		if emailNeedsConflictCheck {
			if emailTaken {
				resp.Email = &registrationAvailabilityField{Available: false, Error: "email_in_use"}
			} else {
				resp.Email = &registrationAvailabilityField{Available: true}
			}
		}
	}

	if phone != "" {
		field, err := s.registrationPhoneAvailability(r, phone)
		if err != nil {
			s.logInternalError(r, "register_availability", "phone_number", "database_error", err)
			serverErr(w, ErrDatabaseError)
			return
		}
		resp.PhoneNumber = field
	}

	writeJSON(w, http.StatusOK, resp)
}

func (s *Service) registrationPhoneAvailability(r *http.Request, phone string) (*registrationAvailabilityField, error) {
	if err := embedded.ValidatePhone(phone); err != nil {
		return &registrationAvailabilityField{Available: false, Error: ErrorCode(embedded.ValidationErrorCode(err)).String()}, nil
	}
	phone = embedded.NormalizePhone(phone)

	phoneTaken, _, err := s.svc.CheckPhoneRegistrationConflict(r.Context(), phone, "")
	if err != nil {
		return nil, err
	}
	if phoneTaken {
		return &registrationAvailabilityField{Available: false, Error: "phone_in_use"}, nil
	}

	return &registrationAvailabilityField{Available: true}, nil
}
