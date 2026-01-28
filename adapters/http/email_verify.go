package authhttp

import (
	"errors"
	"net"
	"net/http"
	"strings"
	"time"

	core "github.com/PaulFidika/authkit/core"
)

func (s *Service) handleEmailVerifyRequestPOST(w http.ResponseWriter, r *http.Request) {
	if !s.svc.HasEmailSender() {
		serverErr(w, "email_verification_unavailable")
		return
	}
	if !s.allow(r, RLEmailVerifyRequest) {
		tooMany(w)
		return
	}
	var req struct {
		Email string `json:"email"`
	}
	if err := decodeJSON(r, &req); err != nil || strings.TrimSpace(req.Email) == "" {
		writeJSON(w, http.StatusOK, map[string]any{"ok": true})
		return
	}
	_ = s.svc.RequestEmailVerification(r.Context(), req.Email, 0)
	writeJSON(w, http.StatusAccepted, map[string]any{"ok": true})
}

func (s *Service) handleEmailVerifyConfirmPOST(w http.ResponseWriter, r *http.Request) {
	if !s.allow(r, RLEmailVerifyConfirm) {
		tooMany(w)
		return
	}
	var req struct {
		Code string `json:"code"`
	}
	if err := decodeJSON(r, &req); err != nil || strings.TrimSpace(req.Code) == "" {
		badRequest(w, "invalid_request")
		return
	}

	code := strings.ToUpper(strings.TrimSpace(req.Code))

	// Try pending registration first (new flow)
	userID, err := s.svc.ConfirmPendingRegistration(r.Context(), code)
	if err == nil && userID != "" {
		if err := s.issueTokensForUser(w, r, userID, "email_verification"); err != nil {
			if errors.Is(err, core.ErrUserBanned) {
				unauthorized(w, "user_banned")
				return
			}
			serverErr(w, "token_issue_failed")
			return
		}
		return
	}

	userID, err = s.svc.ConfirmEmailVerification(r.Context(), code)
	if err != nil {
		badRequest(w, "invalid_or_expired_code")
		return
	}
	if err := s.issueTokensForUser(w, r, userID, "email_verification"); err != nil {
		if errors.Is(err, core.ErrUserBanned) {
			unauthorized(w, "user_banned")
			return
		}
		serverErr(w, "token_issue_failed")
		return
	}
}

func (s *Service) issueTokensForUser(w http.ResponseWriter, r *http.Request, userID string, method string) error {
	ua := r.UserAgent()
	ip := net.ParseIP(clientIP(r))
	sid, rt, _, err := s.svc.IssueRefreshSession(r.Context(), userID, ua, ip)
	if err != nil {
		return err
	}

	ipStr := clientIP(r)
	uaPtr, ipPtr := &ua, &ipStr
	s.svc.LogSessionCreated(r.Context(), userID, method, sid, ipPtr, uaPtr)

	accessToken, exp, err := s.svc.IssueAccessToken(r.Context(), userID, "", map[string]any{"sid": sid})
	if err != nil {
		return err
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"access_token":  accessToken,
		"token_type":    "Bearer",
		"expires_in":    int64(time.Until(exp).Seconds()),
		"refresh_token": rt,
	})
	return nil
}
