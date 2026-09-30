package httpapi

import (
	"net/http"
	"strings"

	"github.com/open-rails/authkit/internal/authflow"
	"github.com/open-rails/authkit/internal/errmodel"
)

func (s *Service) handleLogoutDELETE(w http.ResponseWriter, r *http.Request) {
	cl, err := callerClaims(r)
	if err != nil || strings.TrimSpace(cl.UserID) == "" {
		fail(w, errmodel.CodeUnauthenticated)
		return
	}
	if strings.TrimSpace(cl.SessionID) == "" {
		fail(w, errmodel.CodeMissingSidClaim)
		return
	}
	ctx := authflow.WithSessionRevokeReason(r.Context(), authflow.SessionRevokeReasonLogout)
	if err := s.svc.RevokeSessionByIDForUser(ctx, cl.UserID, cl.SessionID); err != nil {
		serverErr(w, "failed_to_logout", err)
		return
	}
	// ak#271: the server-side session is gone, so the jar value must go too —
	// otherwise the browser keeps posting a dead credential forever.
	s.clearRefreshCookie(w, r)
	noContent(w)
}
