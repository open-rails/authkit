package httpapi

import (
	"net/http"
	"strings"

	"github.com/open-rails/authkit/internal/authflow"
	"github.com/open-rails/authkit/internal/errmodel"
	"github.com/open-rails/authkit/verify"
)

func (s *Service) handleUserSessionsGET(w http.ResponseWriter, r *http.Request) {
	cl, err := verify.GetClaims(r.Context())
	if err != nil || strings.TrimSpace(cl.UserID) == "" {
		fail(w, errmodel.CodeUnauthorized)
		return
	}
	sessions, err := s.svc.ListUserSessions(r.Context(), cl.UserID)
	if err != nil {
		serverErr(w, "failed_to_list", err)
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
		fail(w, errmodel.CodeUnauthorized)
		return
	}
	sid := strings.TrimSpace(r.PathValue("id"))
	if sid == "" {
		fail(w, errmodel.CodeMissingSessionID)
		return
	}
	ctx := authflow.WithSessionRevokeReason(r.Context(), authflow.SessionRevokeReasonUserRevoke)
	if err := s.svc.RevokeSessionByIDForUser(ctx, cl.UserID, sid); err != nil {
		serverErr(w, "failed_to_revoke", err)
		return
	}
	noContent(w)
}

func (s *Service) handleUserSessionsDELETE(w http.ResponseWriter, r *http.Request) {
	cl, err := verify.GetClaims(r.Context())
	if err != nil || strings.TrimSpace(cl.UserID) == "" {
		fail(w, errmodel.CodeUnauthorized)
		return
	}
	ctx := authflow.WithSessionRevokeReason(r.Context(), authflow.SessionRevokeReasonUserRevokeAll)
	if err := s.svc.RevokeIssuerSessions(ctx, cl.UserID, nil); err != nil {
		serverErr(w, "failed_to_revoke_all", err)
		return
	}
	noContent(w)
}
