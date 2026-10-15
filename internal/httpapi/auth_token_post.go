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
	var selected bool
	r, selected = s.activeTenantRefresh(r, body.RefreshToken)
	if !selected {
		fail(w, errmodel.CodeNoSession)
		return
	}
	// A browser with no refresh cookie is simply signed out: a quiet 401 the
	// client settles on, not a malformed request.
	if s.noRefreshCookie(r, body.RefreshToken) {
		fail(w, errmodel.CodeNoSession)
		return
	}
	refreshToken, ok, err := s.refreshTokenFromRequest(r, body.RefreshToken)
	if err != nil {
		serverErr(w, "read_legacy_refresh_cookie", err)
		return
	}
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
		// Only a known credential refusal is a 401. Database, pool and signer
		// failures remain server errors so the client retains its session and
		// retries. Never clear the cookie here: even a stale token can be a
		// lost response after an already committed rotation.
		writeError(w, err)
		return
	}
	s.writeAuthResult(w, r, authflow.LoginOutcome{Kind: authflow.LoginSessionIssued, UserID: userID, Session: &session}, authExtras{})
}
