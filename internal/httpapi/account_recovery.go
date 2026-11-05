package httpapi

import (
	"net/http"

	"github.com/open-rails/authkit/internal/authflow"
	"github.com/open-rails/authkit/internal/errmodel"
)

func (s *Service) handleAccountRecoveryConfirmPOST(w http.ResponseWriter, r *http.Request) {
	var body TokenRequest
	if err := decodeJSON(r, &body); err != nil || body.Token == "" {
		fail(w, errmodel.CodeInvalidRequest)
		return
	}
	out, err := s.svc.ConfirmAccountRecovery(r.Context(), body.Token)
	if err != nil {
		writeError(w, fallback(err, errmodel.CodeInvalidCredentials))
		return
	}
	if out.Kind == authflow.LoginRestored {
		w.WriteHeader(http.StatusNoContent)
		return
	}
	s.writeAuthResult(w, r, out, authExtras{})
}
