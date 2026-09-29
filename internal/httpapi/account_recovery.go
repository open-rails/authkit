package httpapi

import (
	"net/http"

	"github.com/open-rails/authkit/iam"
)

func (s *Service) handleAccountRecoveryConfirmPOST(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Token string `json:"token"`
	}
	if err := decodeJSON(r, &body); err != nil || body.Token == "" {
		badRequest(w, iam.CodeInvalidRequest)
		return
	}
	if err := s.svc.ConfirmAccountRecovery(r.Context(), body.Token); err != nil {
		writeError(w, fallback(err, iam.CodeInvalidCredentials))
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
