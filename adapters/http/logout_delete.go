package authhttp

import (
	"net/http"
	"strings"

	core "github.com/PaulFidika/authkit/core"
)

func (s *Service) handleLogoutDELETE(w http.ResponseWriter, r *http.Request) {
	if !s.allow(r, RLAuthLogout) {
		tooMany(w)
		return
	}

	cl, err := getClaims(r.Context())
	if err != nil || strings.TrimSpace(cl.UserID) == "" {
		unauthorized(w, "unauthorized")
		return
	}
	if strings.TrimSpace(cl.SessionID) == "" {
		badRequest(w, "missing_sid_claim")
		return
	}
	ctx := core.WithSessionRevokeReason(r.Context(), core.SessionRevokeReasonLogout)
	if err := s.svc.RevokeSessionByIDForUser(ctx, cl.UserID, cl.SessionID); err != nil {
		serverErr(w, "failed_to_logout")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}
