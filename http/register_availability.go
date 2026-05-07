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
	Username *registrationAvailabilityField `json:"username,omitempty"`
	Email    *registrationAvailabilityField `json:"email,omitempty"`
}

func (s *Service) handleRegisterAvailabilityGET(w http.ResponseWriter, r *http.Request) {
	if !s.allow(r, RLAuthRegisterAvailability) {
		tooMany(w)
		return
	}

	username := strings.TrimSpace(r.URL.Query().Get("username"))
	email := strings.TrimSpace(r.URL.Query().Get("email"))
	if username == "" && email == "" {
		badRequest(w, "invalid_request")
		return
	}

	resp := registrationAvailabilityResponse{}
	if username != "" {
		field, err := s.registrationUsernameAvailability(r, username)
		if err != nil {
			serverErr(w, "database_error")
			return
		}
		resp.Username = field
	}
	if email != "" {
		field, err := s.registrationEmailAvailability(r, email)
		if err != nil {
			serverErr(w, "database_error")
			return
		}
		resp.Email = field
	}

	writeJSON(w, http.StatusOK, resp)
}

func (s *Service) registrationUsernameAvailability(r *http.Request, username string) (*registrationAvailabilityField, error) {
	if err := validateUsername(username); err != nil {
		return &registrationAvailabilityField{Available: false, Error: err.Error()}, nil
	}

	lookup, err := s.svc.LookupOwnerNamespace(r.Context(), username)
	if err != nil {
		return nil, err
	}
	if lookup != nil && !lookup.Claimable {
		return &registrationAvailabilityField{
			Available: false,
			Error:     registrationUsernameUnavailableError(lookup.Status),
		}, nil
	}

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
	if !strings.Contains(email, "@") {
		return &registrationAvailabilityField{Available: false, Error: "invalid_email"}, nil
	}

	emailTaken, _, err := s.svc.CheckPendingRegistrationConflict(r.Context(), email, "")
	if err != nil {
		return nil, err
	}
	if emailTaken {
		return &registrationAvailabilityField{Available: false, Error: "email_in_use"}, nil
	}

	return &registrationAvailabilityField{Available: true}, nil
}

func registrationUsernameUnavailableError(status core.OwnerNamespaceLookupStatus) string {
	switch status {
	case core.OwnerNamespaceStatusParkedUser,
		core.OwnerNamespaceStatusParkedOrg,
		core.OwnerNamespaceStatusRestrictedName:
		return "username_not_allowed"
	default:
		return "username_in_use"
	}
}
