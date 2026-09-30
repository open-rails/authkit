package httpapi

import (
	"errors"
	"net/http"
	"strings"

	"github.com/open-rails/authkit/internal/authflow"
	"github.com/open-rails/authkit/internal/errmodel"
)

func (s *Service) handleAuthTokenPOST(w http.ResponseWriter, r *http.Request) {
	var body TokenRefreshRequest
	if err := decodeJSON(r, &body); err != nil || !strings.EqualFold(body.GrantType, "refresh_token") {
		fail(w, errmodel.CodeInvalidRequest)
		return
	}
	// A browser with no refresh cookie is simply signed out: a quiet 401 the
	// client settles on, not a malformed request.
	if s.noRefreshCookie(r, body.RefreshToken) {
		fail(w, errmodel.CodeNoSession)
		return
	}
	refreshToken, ok := s.refreshTokenFromRequest(r, body.RefreshToken)
	if !ok {
		fail(w, errmodel.CodeInvalidRequest)
		return
	}
	userID, session, err := s.svc.ExchangeRefreshToken(r.Context(), refreshToken, r.UserAgent(), parseIP(s.requestIP(r)))
	if err != nil {
		// A session that must finish MFA first continues as a sign-in does.
		var continuation *authflow.MFAContinuationRequiredError
		if errors.As(err, &continuation) {
			out, continueErr := s.svc.ContinueRefreshMFA(r.Context(), continuation.UserID, continuation.SessionID)
			if continueErr != nil {
				writeError(w, continueErr)
				return
			}
			s.writeAuthResult(w, r, out, authExtras{})
			return
		}
		if errors.Is(err, errmodel.ErrUserBanned) {
			// Authoritative about the whole browser: the cookie goes.
			s.clearRefreshCookie(w, r)
			fail(w, errmodel.CodeUserBanned)
			return
		}
		// Deliberately NOT cleared here: an unknown token is indistinguishable
		// from a stale one (a lost response after a committed rotation), and
		// clearing would destroy a still-live jar value over a transient
		// failure. The client re-authenticates; the cookie is overwritten then.
		fail(w, errmodel.CodeInvalidToken)
		return
	}
	s.writeAuthResult(w, r, authflow.LoginOutcome{Kind: authflow.LoginSessionIssued, UserID: userID, Session: &session}, authExtras{})
}
