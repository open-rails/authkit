package authhttp

import (
	"errors"
	"net/http"
	"strings"
	"time"

	core "github.com/PaulFidika/authkit/core"
)

func (s *Service) handleUser2FAVerifyPOST(w http.ResponseWriter, r *http.Request) {
	if !s.allow(r, RL2FAVerify) {
		tooMany(w)
		return
	}

	var req struct {
		UserID     string `json:"user_id"`
		Code       string `json:"code"`
		Challenge  string `json:"challenge"`
		BackupCode bool   `json:"backup_code"`
	}
	if err := decodeJSON(r, &req); err != nil {
		badRequest(w, "invalid_request")
		return
	}

	userID := strings.TrimSpace(req.UserID)
	code := strings.TrimSpace(req.Code)
	challenge := strings.TrimSpace(req.Challenge)
	if userID == "" || code == "" || challenge == "" {
		badRequest(w, "missing_fields")
		return
	}

	validChallenge, err := s.svc.Verify2FAChallenge(r.Context(), userID, challenge)
	if err != nil {
		serverErr(w, "challenge_verify_failed")
		return
	}
	if !validChallenge {
		unauthorized(w, "invalid_challenge")
		return
	}

	var valid bool
	if req.BackupCode {
		valid, err = s.svc.VerifyBackupCode(r.Context(), userID, code)
	} else {
		valid, err = s.svc.Verify2FACode(r.Context(), userID, code)
	}
	if err != nil || !valid {
		unauthorized(w, "invalid_code")
		return
	}
	_ = s.svc.Clear2FAChallenge(r.Context(), userID)

	sid, rt, _, err := s.svc.IssueRefreshSession(r.Context(), userID, r.UserAgent(), nil)
	if err != nil {
		if errors.Is(err, core.ErrUserBanned) {
			unauthorized(w, "user_banned")
			return
		}
		serverErr(w, "session_creation_failed")
		return
	}

	ua := r.UserAgent()
	ip := clientIP(r)
	uaPtr, ipPtr := &ua, &ip
	s.svc.LogSessionCreated(r.Context(), userID, "password_login_2fa", sid, ipPtr, uaPtr)

	usr, _ := s.svc.AdminGetUser(r.Context(), userID)
	emailForToken := ""
	if usr != nil && usr.Email != nil {
		emailForToken = *usr.Email
	}

	token, exp, err := s.svc.IssueAccessToken(r.Context(), userID, emailForToken, map[string]any{"sid": sid})
	if err != nil {
		if errors.Is(err, core.ErrUserBanned) {
			unauthorized(w, "user_banned")
			return
		}
		serverErr(w, "token_creation_failed")
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"access_token":  token,
		"token_type":    "Bearer",
		"expires_in":    int64(time.Until(exp).Seconds()),
		"refresh_token": rt,
	})
}
