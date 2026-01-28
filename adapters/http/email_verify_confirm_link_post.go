package authhttp

import (
	"net/http"
	"strings"
)

func (s *Service) handleEmailVerifyConfirmLinkPOST(w http.ResponseWriter, r *http.Request) {
	if !s.allow(r, RLEmailVerifyConfirm) {
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

	_, err := s.svc.ConfirmEmailVerification(r.Context(), strings.TrimSpace(req.Token))
	if err != nil {
		badRequest(w, "invalid_or_expired_token")
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}
