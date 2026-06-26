package authhttp

import (
	"net/http"
	"strings"

	"github.com/open-rails/authkit/embedded"
)

func (s *Service) handleLogoutDELETE(w http.ResponseWriter, r *http.Request) {
	if s.rateLimited(w, r, RLAuthLogout) {
		return
	}

	cl, err := getClaims(r.Context())
	if err != nil || strings.TrimSpace(cl.UserID) == "" {
		unauthorized(w, ErrUnauthorized)
		return
	}
	if strings.TrimSpace(cl.SessionID) == "" {
		badRequest(w, ErrMissingSidClaim)
		return
	}
	ctx := embedded.WithSessionRevokeReason(r.Context(), embedded.SessionRevokeReasonLogout)
	if err := s.svc.RevokeSessionByIDForUser(ctx, cl.UserID, cl.SessionID); err != nil {
		serverErr(w, ErrFailedToLogout)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}
