package authhttp

import (
	"net/http"
	"strings"

	"github.com/open-rails/authkit/verify"

	"github.com/open-rails/authkit/embedded"
)

func (s *Service) handleLogoutDELETE(w http.ResponseWriter, r *http.Request) {
	cl, err := verify.GetClaims(r.Context())
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
	// ak#271: the server-side session is gone, so the jar value must go too —
	// otherwise the browser keeps posting a dead credential forever.
	s.clearRefreshCookie(w, r)
	noContent(w)
}
