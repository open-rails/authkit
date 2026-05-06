package authhttp

import (
	"net/http"
	"strings"
)

func (s *Service) handleAuthSessionsCurrentPOST(w http.ResponseWriter, r *http.Request) {
	if !s.allow(r, RLAuthSessionsCurrent) {
		tooMany(w)
		return
	}
	var body struct {
		RefreshToken string `json:"refresh_token"`
	}
	if err := decodeJSON(r, &body); err != nil || strings.TrimSpace(body.RefreshToken) == "" {
		badRequest(w, "invalid_request")
		return
	}
	sid, err := s.svc.ResolveSessionByRefresh(r.Context(), body.RefreshToken)
	if err != nil || sid == "" {
		unauthorized(w, "invalid_refresh_token")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"session_id": sid})
}
