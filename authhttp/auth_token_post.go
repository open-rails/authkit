package authhttp

import (
	"errors"
	"net/http"
	"strings"
	"time"

	authkit "github.com/open-rails/authkit"
	authcore "github.com/open-rails/authkit/internal/authcore"
)

func (s *Service) handleAuthTokenPOST(w http.ResponseWriter, r *http.Request) {
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
			userID := ""
			if errors.As(err, &ee) {
				userID = ee.UserID
			}
			s.send2FAEnrollmentRequired(w, r, userID)
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
	s.writeTokenSet(w, r, http.StatusOK, authkit.NewTokenSet(accessToken, newRT, exp))
}

// send2FAEnrollmentRequired answers the 403 2fa_enrollment_required envelope
// (#313). With a user id it also mints the enrollment-only token (#148 note
// b) under metadata.token_set so the client can reach the enroll routes.
func (s *Service) send2FAEnrollmentRequired(w http.ResponseWriter, r *http.Request, userID string) {
	metadata := map[string]any{
		"requires_2fa_enrollment": true,
		"allowed_methods":         s.svc.TwoFactorAllowedMethods(),
	}
	if userID != "" {
		token, exp, err := s.svc.Mint2FAEnrollmentToken(r.Context(), userID)
		if err != nil {
			serverErr(w, ErrTokenIssueFailed)
			return
		}
		metadata["token_set"] = authkit.TokenSet{AccessToken: token, TokenType: "Bearer", ExpiresIn: int64(time.Until(exp).Seconds())}
	}
	sendErrData(w, http.StatusForbidden, ErrTwoFAEnrollmentRequired, metadata)
}

// send2FAEnrollmentRequiredError is the tokenless form for callers without a
// user id (or a request).
func (s *Service) send2FAEnrollmentRequiredError(w http.ResponseWriter) {
	sendErrData(w, http.StatusForbidden, ErrTwoFAEnrollmentRequired, map[string]any{
		"requires_2fa_enrollment": true,
		"allowed_methods":         s.svc.TwoFactorAllowedMethods(),
	})
}
