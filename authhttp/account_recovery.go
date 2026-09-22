package authhttp

import (
	authkit "github.com/open-rails/authkit"
	"net/http"
)

func (s *Service) handleAccountRecoveryConfirmPOST(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Token string `json:"token"`
	}
	if err := decodeJSON(r, &body); err != nil || body.Token == "" {
		badRequest(w, authkit.CodeInvalidRequest)
		return
	}
	if err := s.svc.ConfirmAccountRecovery(r.Context(), body.Token); err != nil {
		writeError(w, fallback(err, authkit.CodeInvalidCredentials))
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
