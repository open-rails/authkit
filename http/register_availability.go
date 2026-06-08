package authhttp

import (
	"net/http"
	"strings"

	core "github.com/open-rails/authkit/core"
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
		badRequest(w, "invalid_request")
		return
	}

	// When public registration is disabled, never report a name or email as
	// usable: every requested field is unavailable with a stable reason.
	if s.publicRegistrationDisabled() {
		resp := registrationAvailabilityResponse{}
		if username != "" {
			resp.Username = &registrationAvailabilityField{Available: false, Error: errRegistrationDisabled}
		}
		if email != "" {
			resp.Email = &registrationAvailabilityField{Available: false, Error: errRegistrationDisabled}
		}
		if phone != "" {
			resp.PhoneNumber = &registrationAvailabilityField{Available: false, Error: errRegistrationDisabled}
		}
		writeJSON(w, http.StatusOK, resp)
		return
	}

	resp := registrationAvailabilityResponse{}
	if username != "" {
		field, err := s.registrationUsernameAvailability(r, username)
		if err != nil {
			s.logInternalError(r, "register_availability", "username", "database_error", err)
			serverErr(w, "database_error")
			return
		}
		resp.Username = field
	}
	if email != "" {
		field, err := s.registrationEmailAvailability(r, email)
		if err != nil {
			s.logInternalError(r, "register_availability", "email", "database_error", err)
			serverErr(w, "database_error")
			return
		}
		resp.Email = field
	}
	if phone != "" {
		field, err := s.registrationPhoneAvailability(r, phone)
		if err != nil {
			s.logInternalError(r, "register_availability", "phone_number", "database_error", err)
			serverErr(w, "database_error")
			return
		}
		resp.PhoneNumber = field
	}

	writeJSON(w, http.StatusOK, resp)
}

func (s *Service) registrationUsernameAvailability(r *http.Request, username string) (*registrationAvailabilityField, error) {
	if _, err := s.svc.ValidateUsernameForRegistration(r.Context(), username); err != nil {
		if code := core.ValidationErrorCode(err); code != "" {
			return &registrationAvailabilityField{Available: false, Error: code}, nil
		}
		return nil, err
	}
	username = strings.TrimSpace(username)

	_, usernameTaken, err := s.svc.CheckPendingRegistrationConflict(r.Context(), "", username)
	if err != nil {
		return nil, err
	}
	if usernameTaken {
		return &registrationAvailabilityField{Available: false, Error: "username_in_use"}, nil
	}

	return &registrationAvailabilityField{Available: true}, nil
}

func (s *Service) registrationEmailAvailability(r *http.Request, email string) (*registrationAvailabilityField, error) {
	if err := core.ValidateEmail(email); err != nil {
		return &registrationAvailabilityField{Available: false, Error: core.ValidationErrorCode(err)}, nil
	}
	email = core.NormalizeEmail(email)

	emailTaken, _, err := s.svc.CheckPendingRegistrationConflict(r.Context(), email, "")
	if err != nil {
		return nil, err
	}
	if emailTaken {
		return &registrationAvailabilityField{Available: false, Error: "email_in_use"}, nil
	}

	return &registrationAvailabilityField{Available: true}, nil
}

func (s *Service) registrationPhoneAvailability(r *http.Request, phone string) (*registrationAvailabilityField, error) {
	if err := core.ValidatePhone(phone); err != nil {
		return &registrationAvailabilityField{Available: false, Error: core.ValidationErrorCode(err)}, nil
	}
	phone = core.NormalizePhone(phone)

	phoneTaken, _, err := s.svc.CheckPhoneRegistrationConflict(r.Context(), phone, "")
	if err != nil {
		return nil, err
	}
	if phoneTaken {
		return &registrationAvailabilityField{Available: false, Error: "phone_in_use"}, nil
	}

	return &registrationAvailabilityField{Available: true}, nil
}
