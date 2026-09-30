package httpapi

import (
	"net/http"
	"strings"

	"github.com/open-rails/authkit/internal/authflow"
	"github.com/open-rails/authkit/internal/errmodel"
)

func (s *Service) handleUserSessionsGET(w http.ResponseWriter, r *http.Request) {
	cl, err := callerClaims(r)
	if err != nil || strings.TrimSpace(cl.UserID) == "" {
		fail(w, errmodel.CodeUnauthenticated)
		return
	}
	sessions, err := s.svc.Sessions(r.Context(), cl.UserID)
	if err != nil {
		serverErr(w, "failed_to_list", err)
		return
	}
	for i := range sessions {
		sessions[i].Current = sessions[i].ID == cl.SessionID
	}
	all(w, sessions)
}

func (s *Service) handleUserSessionDELETE(w http.ResponseWriter, r *http.Request) {
	cl, err := callerClaims(r)
	if err != nil || strings.TrimSpace(cl.UserID) == "" {
		fail(w, errmodel.CodeUnauthenticated)
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
	cl, err := callerClaims(r)
	if err != nil || strings.TrimSpace(cl.UserID) == "" {
		fail(w, errmodel.CodeUnauthenticated)
		return
	}
	ctx := authflow.WithSessionRevokeReason(r.Context(), authflow.SessionRevokeReasonUserRevokeAll)
	if err := s.svc.RevokeIssuerSessions(ctx, cl.UserID, nil); err != nil {
		serverErr(w, "failed_to_revoke_all", err)
		return
	}
	noContent(w)
}
