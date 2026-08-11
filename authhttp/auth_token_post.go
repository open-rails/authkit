package authhttp

import (
	"errors"
	authkit "github.com/open-rails/authkit"
	authcore "github.com/open-rails/authkit/internal/authcore"
	"net/http"
	"strings"
	"time"
)

func (s *Service) handleAuthTokenPOST(w http.ResponseWriter, r *http.Request) {
	if s.rateLimited(w, r, RLAuthToken) {
		return
	}

	var body struct {
		GrantType    string `json:"grant_type"`
		RefreshToken string `json:"refresh_token"`
	}
	if err := decodeJSON(r, &body); err != nil || !strings.EqualFold(body.GrantType, "refresh_token") {
		badRequest(w, ErrInvalidRequest)
		return
	}
	// ak#271: the credential is the body's when the client still holds one,
	// otherwise the HttpOnly cookie. A cookie-only client sends an empty
	// refresh_token and must NOT be answered with a 400 — that is the steady
	// state after the migration, not a malformed request.
	refreshToken, ok := s.refreshTokenFromRequest(r, body.RefreshToken)
	if !ok {
		badRequest(w, ErrInvalidRequest)
		return
	}
	ua := r.UserAgent()
	ip := parseIP(remoteIP(r))
	accessToken, exp, newRT, err := s.svc.ExchangeRefreshToken(r.Context(), refreshToken, ua, ip)
	if err != nil {
		if errors.Is(err, authkit.ErrTwoFAEnrollmentRequired) {
			// #148 note b: hand back a usable enrollment token (like the login
			// path) so a refresh-gated user can reach the enroll routes instead of
			// a dead-end token-less 403.
			var ee *authcore.TwoFAEnrollmentRequiredError
			if errors.As(err, &ee) && ee.UserID != "" {
				s.write2FAEnrollmentRequired(w, r, ee.UserID)
				return
			}
			s.send2FAEnrollmentRequiredError(w)
			return
		}
		if errors.Is(err, authkit.ErrUserBanned) {
			// Authoritative about the whole browser: the cookie goes.
			s.clearRefreshCookie(w, r)
			unauthorized(w, ErrUserBanned)
			return
		}
		// Deliberately NOT cleared here: an unknown token is indistinguishable
		// from a stale one (a lost response after a committed rotation), and
		// clearing would destroy a still-live jar value over a transient
		// failure. The client re-authenticates; the cookie is overwritten then.
		unauthorized(w, ErrInvalidRefreshToken)
		return
	}

	// #180: the /token refresh response now emits the full §6.3 token-pair envelope
	// (previously omitted token_type) — an additive, contract-conforming change.
	s.writeAccessTokenJSON(w, r, http.StatusOK, newAuthTokens(accessToken, newRT, exp), nil)
}

func (s *Service) send2FAEnrollmentRequiredError(w http.ResponseWriter) {
	sendErrData(w, http.StatusForbidden, ErrTwoFAEnrollmentRequired, map[string]any{
		"requires_2fa_enrollment": true,
		"allowed_methods":         s.svc.TwoFactorAllowedMethods(),
	})
}

func (s *Service) write2FAEnrollmentRequired(w http.ResponseWriter, r *http.Request, userID string) {
	token, exp, err := s.svc.Mint2FAEnrollmentToken(r.Context(), userID)
	if err != nil {
		serverErr(w, ErrTokenIssueFailed)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"error":                   ErrTwoFAEnrollmentRequired,
		"requires_2fa_enrollment": true,
		"allowed_methods":         s.svc.TwoFactorAllowedMethods(),
		"access_token":            token,
		"token_type":              "Bearer",
		"expires_in":              int64(time.Until(exp).Seconds()),
	})
}
