package authhttp

import (
	"net/http"
	"strings"

	"github.com/open-rails/authkit/embedded"
)

func (s *Service) handleUserSessionsGET(w http.ResponseWriter, r *http.Request) {
	if s.rateLimited(w, r, RLAuthSessionsList) {
		return
	}
	cl, err := getClaims(r.Context())
	if err != nil || strings.TrimSpace(cl.UserID) == "" {
		unauthorized(w, ErrUnauthorized)
		return
	}
	sessions, err := s.svc.ListUserSessions(r.Context(), cl.UserID)
	if err != nil {
		serverErr(w, ErrFailedToList)
		return
	}
	arr := make([]map[string]any, 0, len(sessions))
	for _, sess := range sessions {
		arr = append(arr, map[string]any{
			"session_id":   sess.ID,
			"family_id":    sess.FamilyID,
			"created_at":   sess.CreatedAt,
			"last_used_at": sess.LastUsedAt,
			"expires_at":   sess.ExpiresAt,
			"ip":           sess.IPAddr,
			"ua":           sess.UserAgent,
		})
	}
	writeJSON(w, http.StatusOK, map[string]any{"data": arr})
}

func (s *Service) handleUserSessionDELETE(w http.ResponseWriter, r *http.Request) {
	if s.rateLimited(w, r, RLAuthSessionsRevoke) {
		return
	}
	cl, err := getClaims(r.Context())
	if err != nil || strings.TrimSpace(cl.UserID) == "" {
		unauthorized(w, ErrUnauthorized)
		return
	}
	sid := strings.TrimSpace(r.PathValue("id"))
	if sid == "" {
		badRequest(w, ErrMissingSessionID)
		return
	}
	ctx := embedded.WithSessionRevokeReason(r.Context(), embedded.SessionRevokeReasonUserRevoke)
	if err := s.svc.RevokeSessionByIDForUser(ctx, cl.UserID, sid); err != nil {
		serverErr(w, ErrFailedToRevoke)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func (s *Service) handleUserSessionsDELETE(w http.ResponseWriter, r *http.Request) {
	if s.rateLimited(w, r, RLAuthSessionsRevokeAll) {
		return
	}
	cl, err := getClaims(r.Context())
	if err != nil || strings.TrimSpace(cl.UserID) == "" {
		unauthorized(w, ErrUnauthorized)
		return
	}
	ctx := embedded.WithSessionRevokeReason(r.Context(), embedded.SessionRevokeReasonUserRevokeAll)
	if err := s.svc.RevokeAllSessions(ctx, cl.UserID, nil); err != nil {
		serverErr(w, ErrFailedToRevokeAll)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}
