package authhttp

import (
	"net/http"
	"strings"
)

func (s *Service) handlePhoneVerifyConfirmLinkPOST(w http.ResponseWriter, r *http.Request) {
	if !s.allow(r, RLPhoneVerifyConfirm) {
		tooMany(w)
		return
	}

	var req struct {
		Token string `json:"token"`
	}
	if err := decodeJSON(r, &req); err != nil || strings.TrimSpace(req.Token) == "" {
		badRequest(w, "invalid_request")
		return
	}

	token := strings.TrimSpace(req.Token)
	if userID, err := s.svc.ConfirmPendingPhoneRegistrationByToken(r.Context(), token); err == nil && strings.TrimSpace(userID) != "" {
		writeJSON(w, http.StatusOK, map[string]any{"ok": true, "user_id": userID})
		return
	}
	if err := s.svc.ConfirmPhoneVerificationByToken(r.Context(), token); err == nil {
		writeJSON(w, http.StatusOK, map[string]any{"ok": true})
		return
	}

	badRequest(w, "invalid_or_expired_token")
}
