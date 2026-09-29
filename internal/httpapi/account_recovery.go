package httpapi

import (
	"net/http"

	"github.com/open-rails/authkit/internal/errmodel"
)

func (s *Service) handleAccountRecoveryConfirmPOST(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Token string `json:"token"`
	}
	if err := decodeJSON(r, &body); err != nil || body.Token == "" {
		fail(w, errmodel.CodeInvalidRequest)
		return
	}
	if err := s.svc.ConfirmAccountRecovery(r.Context(), body.Token); err != nil {
		writeError(w, fallback(err, errmodel.CodeInvalidCredentials))
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
