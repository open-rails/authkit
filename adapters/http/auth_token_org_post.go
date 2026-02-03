package authhttp

import (
	"errors"
	"net/http"
	"strings"
	"time"

	core "github.com/open-rails/authkit/core"
)

func (s *Service) handleAuthTokenOrgPOST(w http.ResponseWriter, r *http.Request) {
	// Reuse auth token rate limit bucket.
	if !s.allow(r, RLAuthToken) {
		tooMany(w)
		return
	}

	claims, ok := ClaimsFromContext(r.Context())
	if !ok || strings.TrimSpace(claims.UserID) == "" {
		unauthorized(w, "unauthorized")
		return
	}

	var body struct {
		Org string `json:"org"`
	}
	if err := decodeJSON(r, &body); err != nil || strings.TrimSpace(body.Org) == "" {
		badRequest(w, "invalid_request")
		return
	}

	email := strings.TrimSpace(claims.Email)
	if email == "" {
		if u, err := s.svc.AdminGetUser(r.Context(), claims.UserID); err == nil && u != nil && u.Email != nil {
			email = *u.Email
		}
	}

	extra := map[string]any{}
	if strings.TrimSpace(claims.SessionID) != "" {
		extra["sid"] = claims.SessionID
	}
	token, exp, err := s.svc.IssueOrgAccessToken(r.Context(), claims.UserID, email, body.Org, extra)
	if err != nil {
		if errors.Is(err, core.ErrNotOrgMember) {
			forbidden(w, "not_org_member")
			return
		}
		if errors.Is(err, core.ErrOrgNotFound) {
			notFound(w, "org_not_found")
			return
		}
		serverErr(w, "token_issue_failed")
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"access_token": token,
		"token_type":   "Bearer",
		"expires_in":   int64(time.Until(exp).Seconds()),
	})
}
