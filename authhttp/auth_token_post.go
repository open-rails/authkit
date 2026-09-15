package authhttp

import (
	"errors"
	"net/http"
	"strings"

	authkit "github.com/open-rails/authkit"
	"github.com/open-rails/authkit/embedded"
)

func (s *Service) handleAuthTokenPOST(w http.ResponseWriter, r *http.Request) {
	var body struct {
		GrantType    string `json:"grant_type"`
		RefreshToken string `json:"refresh_token"`
	}
	if err := decodeJSON(r, &body); err != nil || !strings.EqualFold(body.GrantType, "refresh_token") {
		badRequest(w, authkit.CodeInvalidRequest)
		return
	}
	refreshToken, ok := s.refreshTokenFromRequest(r, body.RefreshToken)
	if !ok {
		badRequest(w, authkit.CodeInvalidRequest)
		return
	}
	ua := r.UserAgent()
	ip := parseIP(s.requestIP(r))
	accessToken, exp, newRT, err := s.svc.ExchangeRefreshToken(r.Context(), refreshToken, ua, ip)
	if err != nil {
		var continuation *embedded.MFAContinuationRequiredError
		if errors.As(err, &continuation) {
			out, continueErr := s.svc.ContinueRefreshMFA(r.Context(), continuation.UserID, continuation.SessionID)
			if continueErr != nil {
				writeError(w, continueErr)
				return
			}
			s.writeLoginContinuation(w, r, out, nil)
			return
		}
		if errors.Is(err, authkit.ErrUserBanned) {
			// Authoritative about the whole browser: the cookie goes.
			s.clearRefreshCookie(w, r)
			unauthorized(w, authkit.CodeUserBanned)
			return
		}
		// Deliberately NOT cleared here: an unknown token is indistinguishable
		// from a stale one (a lost response after a committed rotation), and
		// clearing would destroy a still-live jar value over a transient
		// failure. The client re-authenticates; the cookie is overwritten then.
		unauthorized(w, authkit.CodeInvalidRefreshToken)
		return
	}

	// #180: the /token refresh response now emits the full §6.3 token-pair envelope
	// (previously omitted token_type) — an additive, contract-conforming change.
	s.writeTokenSet(w, r, http.StatusOK, authkit.NewTokenSet(accessToken, newRT, exp))
}

// send2FAEnrollmentRequiredError is the tokenless form for callers without a
// user id (or a request).
func (s *Service) send2FAEnrollmentRequiredError(w http.ResponseWriter) {
	sendErrData(w, http.StatusForbidden, authkit.CodeTwoFAEnrollmentRequired, map[string]any{
		"requires_2fa_enrollment": true,
		"allowed_methods":         s.svc.TwoFactorAllowedMethods(),
	})
}
