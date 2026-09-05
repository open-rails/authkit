package authhttp

import (
	"net/http"
	"strings"

	authkit "github.com/open-rails/authkit"
	"github.com/open-rails/authkit/verify"

	"github.com/open-rails/authkit/embedded"
)

func (s *Service) handleUserSessionsGET(w http.ResponseWriter, r *http.Request) {
	cl, err := verify.GetClaims(r.Context())
	if err != nil || strings.TrimSpace(cl.UserID) == "" {
		unauthorized(w, authkit.CodeUnauthorized)
		return
	}
	sessions, err := s.svc.ListUserSessions(r.Context(), cl.UserID)
	if err != nil {
		serverErr(w, authkit.CodeFailedToList)
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
	writeList(w, arr, "")
}

func (s *Service) handleUserSessionDELETE(w http.ResponseWriter, r *http.Request) {
	cl, err := verify.GetClaims(r.Context())
	if err != nil || strings.TrimSpace(cl.UserID) == "" {
		unauthorized(w, authkit.CodeUnauthorized)
		return
	}
	sid := strings.TrimSpace(r.PathValue("id"))
	if sid == "" {
		badRequest(w, authkit.CodeMissingSessionID)
		return
	}
	ctx := embedded.WithSessionRevokeReason(r.Context(), embedded.SessionRevokeReasonUserRevoke)
	if err := s.svc.RevokeSessionByIDForUser(ctx, cl.UserID, sid); err != nil {
		serverErr(w, authkit.CodeFailedToRevoke)
		return
	}
	noContent(w)
}

func (s *Service) handleUserSessionsDELETE(w http.ResponseWriter, r *http.Request) {
	cl, err := verify.GetClaims(r.Context())
	if err != nil || strings.TrimSpace(cl.UserID) == "" {
		unauthorized(w, authkit.CodeUnauthorized)
		return
	}
	ctx := embedded.WithSessionRevokeReason(r.Context(), embedded.SessionRevokeReasonUserRevokeAll)
	if err := s.svc.RevokeAllSessions(ctx, cl.UserID, nil); err != nil {
		serverErr(w, authkit.CodeFailedToRevokeAll)
		return
	}
	noContent(w)
}
