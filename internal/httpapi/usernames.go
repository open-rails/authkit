package httpapi

import (
	"github.com/open-rails/authkit/internal/authflow"
	"github.com/open-rails/authkit/internal/errmodel"
	"net/http"
)

func (s *Service) handleUsernameGenerateGET(w http.ResponseWriter, r *http.Request) {
	name, err := s.svc.GenerateUsername(r.Context())
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, UsernameCandidate{Username: name})
}
func (s *Service) handleUsernameAvailabilityGET(w http.ResponseWriter, r *http.Request) {
	var q UsernameQuery
	if !readQuery(w, r, &q) {
		return
	}
	if q.Username == "" {
		fail(w, errmodel.CodeInvalidRequest)
		return
	}
	if err := s.svc.CheckUsername(r.Context(), q.Username); err != nil {
		if code := authflow.ValidationErrorCode(err); code != "" {
			writeJSON(w, http.StatusOK, unavailable(code.String()))
		} else {
			writeError(w, err)
		}
		return
	}
	writeJSON(w, http.StatusOK, AvailabilityField{Available: true})
}
