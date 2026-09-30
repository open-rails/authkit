package httpapi

import (
	"errors"
	"net/http"
	"strings"

	jwt "github.com/golang-jwt/jwt/v5"

	"github.com/open-rails/authkit/internal/authflow"
	"github.com/open-rails/authkit/internal/errmodel"
)

// handleLogoutDELETE ends the caller's sign-in: the refresh session behind
// the token, or a device-key token's own key. Ending one already ended is
// done, so the route needs only a valid token.
func (s *Service) handleLogoutDELETE(w http.ResponseWriter, r *http.Request) {
	cl, err := callerClaims(r)
	if err != nil || strings.TrimSpace(cl.UserID) == "" {
		fail(w, errmodel.CodeUnauthenticated)
		return
	}
	switch {
	case strings.TrimSpace(cl.SessionID) != "":
		ctx := authflow.WithSessionRevokeReason(r.Context(), authflow.SessionRevokeReasonLogout)
		if err := s.svc.RevokeSessionByIDForUser(ctx, cl.UserID, cl.SessionID); err != nil {
			serverErr(w, "failed_to_logout", err)
			return
		}
		// ak#271: the server-side session is gone, so the jar value must go
		// too; otherwise the browser keeps posting a dead credential forever.
		s.clearRefreshCookie(w, r)
	case strings.TrimSpace(cl.DeviceKeyID) != "":
		// A key already gone (purged) is signed out too.
		if err := s.svc.RevokeDeviceKey(r.Context(), cl.UserID, cl.DeviceKeyID, cl.DeviceKeyID); err != nil && !errors.Is(err, jwt.ErrTokenUnverifiable) {
			serverErr(w, "failed_to_logout", err)
			return
		}
	default:
		fail(w, errmodel.CodeMissingSidClaim)
		return
	}
	noContent(w)
}
