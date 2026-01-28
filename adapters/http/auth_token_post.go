package authhttp

import (
	"errors"
	"net/http"
	"strings"
	"time"

	core "github.com/PaulFidika/authkit/core"
)

func (s *Service) handleAuthTokenPOST(w http.ResponseWriter, r *http.Request) {
	if !s.allow(r, RLAuthToken) {
		tooMany(w)
		return
	}

	var body struct {
		GrantType    string `json:"grant_type"`
		RefreshToken string `json:"refresh_token"`
	}
	if err := decodeJSON(r, &body); err != nil || !strings.EqualFold(body.GrantType, "refresh_token") || strings.TrimSpace(body.RefreshToken) == "" {
		badRequest(w, "invalid_request")
		return
	}

	ua := r.UserAgent()
	ip := parseIP(clientIP(r))
	accessToken, exp, newRT, err := s.svc.ExchangeRefreshToken(r.Context(), body.RefreshToken, ua, ip)
	if err != nil {
		if errors.Is(err, core.ErrUserBanned) {
			unauthorized(w, "user_banned")
			return
		}
		unauthorized(w, "invalid_refresh_token")
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"access_token":  accessToken,
		"expires_in":    int(time.Until(exp).Seconds()),
		"refresh_token": newRT,
	})
}
