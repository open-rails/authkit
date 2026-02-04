package authhttp

import (
	"errors"
	"net/http"
	"strings"
	"time"

	core "github.com/open-rails/authkit/core"
)

func (s *Service) handleAuthTokenPOST(w http.ResponseWriter, r *http.Request) {
	if !s.allow(r, RLAuthToken) {
		tooMany(w)
		return
	}

	var body struct {
		GrantType    string `json:"grant_type"`
		RefreshToken string `json:"refresh_token"`
		Org          string `json:"org"`
	}
	if err := decodeJSON(r, &body); err != nil || !strings.EqualFold(body.GrantType, "refresh_token") || strings.TrimSpace(body.RefreshToken) == "" {
		badRequest(w, "invalid_request")
		return
	}
	if strings.TrimSpace(body.Org) != "" && !strings.EqualFold(strings.TrimSpace(s.svc.Options().OrgMode), "multi") {
		badRequest(w, "org_not_supported")
		return
	}

	ua := r.UserAgent()
	ip := parseIP(clientIP(r))
	var accessToken string
	var exp time.Time
	var newRT string
	var err error
	if strings.TrimSpace(body.Org) != "" && strings.EqualFold(strings.TrimSpace(s.svc.Options().OrgMode), "multi") {
		accessToken, exp, newRT, err = s.svc.ExchangeRefreshTokenWithOrg(r.Context(), body.RefreshToken, ua, ip, body.Org)
	} else {
		accessToken, exp, newRT, err = s.svc.ExchangeRefreshToken(r.Context(), body.RefreshToken, ua, ip)
	}
	if err != nil {
		if errors.Is(err, core.ErrUserBanned) {
			unauthorized(w, "user_banned")
			return
		}
		if errors.Is(err, core.ErrNotOrgMember) {
			forbidden(w, "not_org_member")
			return
		}
		if errors.Is(err, core.ErrOrgNotFound) {
			notFound(w, "org_not_found")
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
