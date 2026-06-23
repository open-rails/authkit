package authhttp

import (
	"errors"
	"net/http"
	"strings"
	"time"

	core "github.com/open-rails/authkit/core"
)

func (s *Service) handleAuthTokenPOST(w http.ResponseWriter, r *http.Request) {
	if s.rateLimited(w, r, RLAuthToken) {
		return
	}

	var body struct {
		GrantType    string `json:"grant_type"`
		RefreshToken string `json:"refresh_token"`
	}
	if err := decodeJSON(r, &body); err != nil || !strings.EqualFold(body.GrantType, "refresh_token") || strings.TrimSpace(body.RefreshToken) == "" {
		badRequest(w, ErrInvalidRequest)
		return
	}
	ua := r.UserAgent()
	ip := parseIP(clientIP(r))
	accessToken, exp, newRT, err := s.svc.ExchangeRefreshToken(r.Context(), body.RefreshToken, ua, ip)
	if err != nil {
		if errors.Is(err, core.ErrTwoFAEnrollmentRequired) {
			send2FAEnrollmentRequiredError(w)
			return
		}
		if errors.Is(err, core.ErrUserBanned) {
			unauthorized(w, ErrUserBanned)
			return
		}
		unauthorized(w, ErrInvalidRefreshToken)
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"access_token":  accessToken,
		"expires_in":    int(time.Until(exp).Seconds()),
		"refresh_token": newRT,
	})
}

func send2FAEnrollmentRequiredError(w http.ResponseWriter) {
	sendErrData(w, http.StatusForbidden, ErrTwoFAEnrollmentRequired, map[string]any{
		"requires_2fa_enrollment": true,
		"allowed_methods":         []string{"email", "sms", "totp"},
	})
}

func (s *Service) write2FAEnrollmentRequired(w http.ResponseWriter, r *http.Request, userID string) {
	token, exp, err := s.svc.Issue2FAEnrollmentToken(r.Context(), userID)
	if err != nil {
		serverErr(w, ErrTokenIssueFailed)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"error":                   ErrTwoFAEnrollmentRequired,
		"requires_2fa_enrollment": true,
		"allowed_methods":         []string{"email", "sms", "totp"},
		"access_token":            token,
		"token_type":              "Bearer",
		"expires_in":              int64(time.Until(exp).Seconds()),
	})
}
