package authhttp

import (
	"net/http"
	"strings"

	core "github.com/PaulFidika/authkit/core"
)

func (s *Service) handleUserSessionsGET(w http.ResponseWriter, r *http.Request) {
	if !s.allow(r, RLAuthSessionsList) {
		tooMany(w)
		return
	}
	cl, err := getClaims(r.Context())
	if err != nil || strings.TrimSpace(cl.UserID) == "" {
		unauthorized(w, "unauthorized")
		return
	}
	sessions, err := s.svc.ListUserSessions(r.Context(), cl.UserID)
	if err != nil {
		serverErr(w, "failed_to_list")
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
	if !s.allow(r, RLAuthSessionsRevoke) {
		tooMany(w)
		return
	}
	cl, err := getClaims(r.Context())
	if err != nil || strings.TrimSpace(cl.UserID) == "" {
		unauthorized(w, "unauthorized")
		return
	}
	sid := strings.TrimSpace(r.PathValue("id"))
	if sid == "" {
		badRequest(w, "missing_session_id")
		return
	}
	ctx := core.WithSessionRevokeReason(r.Context(), core.SessionRevokeReasonUserRevoke)
	if err := s.svc.RevokeSessionByIDForUser(ctx, cl.UserID, sid); err != nil {
		serverErr(w, "failed_to_revoke")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func (s *Service) handleUserSessionsDELETE(w http.ResponseWriter, r *http.Request) {
	if !s.allow(r, RLAuthSessionsRevokeAll) {
		tooMany(w)
		return
	}
	cl, err := getClaims(r.Context())
	if err != nil || strings.TrimSpace(cl.UserID) == "" {
		unauthorized(w, "unauthorized")
		return
	}
	ctx := core.WithSessionRevokeReason(r.Context(), core.SessionRevokeReasonUserRevokeAll)
	if err := s.svc.RevokeAllSessions(ctx, cl.UserID, nil); err != nil {
		serverErr(w, "failed_to_revoke_all")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}
