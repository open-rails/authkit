package httpapi

import (
	"errors"
	"net/http"
	"strings"

	"github.com/open-rails/authkit/iam"
	"github.com/open-rails/authkit/internal/authflow"
	"github.com/open-rails/authkit/internal/errmodel"
)

func (s *Service) handleAuthTokenPOST(w http.ResponseWriter, r *http.Request) {
	var body struct {
		GrantType    string `json:"grant_type"`
		RefreshToken string `json:"refresh_token"`
	}
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
	ua := r.UserAgent()
	ip := parseIP(s.requestIP(r))
	accessToken, exp, newRT, err := s.svc.ExchangeRefreshToken(r.Context(), refreshToken, ua, ip)
	if err != nil {
		var continuation *authflow.MFAContinuationRequiredError
		if errors.As(err, &continuation) {
			out, continueErr := s.svc.ContinueRefreshMFA(r.Context(), continuation.UserID, continuation.SessionID)
			if continueErr != nil {
				writeError(w, continueErr)
				return
			}
			s.writeLoginContinuation(w, r, out, nil)
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

	// #180: the /token refresh response now emits the full §6.3 token-pair envelope
	// (previously omitted token_type) — an additive, contract-conforming change.
	s.writeTokenSet(w, r, http.StatusOK, iam.NewTokenSet(accessToken, newRT, exp))
}

// send2FAEnrollmentRequiredError is the tokenless form for callers without a
// user id (or a request).
func (s *Service) send2FAEnrollmentRequiredError(w http.ResponseWriter) {
	fail(w, errmodel.CodeTwoFAEnrollmentRequired, errmodel.WithMetadata(map[string]any{
		"requires_2fa_enrollment": true,
		"allowed_methods":         s.svc.TwoFactorAllowedMethods(),
	}))
}
