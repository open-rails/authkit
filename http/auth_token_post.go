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
		Tenant       string `json:"tenant"`
	}
	if err := decodeJSON(r, &body); err != nil || !strings.EqualFold(body.GrantType, "refresh_token") || strings.TrimSpace(body.RefreshToken) == "" {
		badRequest(w, "invalid_request")
		return
	}
	if strings.TrimSpace(body.Tenant) != "" && !strings.EqualFold(strings.TrimSpace(s.svc.Options().TenantMode), "multi") {
		badRequest(w, "tenant_not_supported")
		return
	}

	ua := r.UserAgent()
	ip := parseIP(clientIP(r))
	var accessToken string
	var exp time.Time
	var newRT string
	var err error
	if strings.TrimSpace(body.Tenant) != "" && strings.EqualFold(strings.TrimSpace(s.svc.Options().TenantMode), "multi") {
		accessToken, exp, newRT, err = s.svc.ExchangeRefreshTokenWithTenant(r.Context(), body.RefreshToken, ua, ip, body.Tenant)
	} else {
		accessToken, exp, newRT, err = s.svc.ExchangeRefreshToken(r.Context(), body.RefreshToken, ua, ip)
	}
	if err != nil {
		if errors.Is(err, core.ErrUserBanned) {
			unauthorized(w, "user_banned")
			return
		}
		if errors.Is(err, core.ErrNotTenantMember) {
			forbidden(w, "not_tenant_member")
			return
		}
		if errors.Is(err, core.ErrTenantNotFound) {
			notFound(w, "tenant_not_found")
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
