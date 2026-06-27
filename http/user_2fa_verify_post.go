package authhttp

import (
	"errors"
	authkit "github.com/open-rails/authkit"
	"net/http"
	"strings"
	"time"
)

func (s *Service) handleUser2FAVerifyPOST(w http.ResponseWriter, r *http.Request) {
	if s.rateLimited(w, r, RL2FAVerify) {
		return
	}

	var req struct {
		UserID     string `json:"user_id"`
		Code       string `json:"code"`
		Challenge  string `json:"challenge"`
		FactorID   string `json:"factor_id"`
		BackupCode bool   `json:"backup_code"`
	}
	if err := decodeJSON(r, &req); err != nil {
		badRequest(w, ErrInvalidRequest)
		return
	}

	userID := strings.TrimSpace(req.UserID)
	code := strings.TrimSpace(req.Code)
	challenge := strings.TrimSpace(req.Challenge)
	if userID == "" || code == "" || challenge == "" {
		badRequest(w, ErrMissingFields)
		return
	}

	// Per-identifier check: a 2FA code is 6 numeric digits with a 10-minute TTL,
	// and a failed attempt does not consume it. Capping per user_id (not just per
	// IP) prevents distributed brute-force against one account's second factor
	// from many IPs, each spending their own per-IP budget.
	if s.rateLimitedByIdentifier(w, r, RL2FAVerify, userID) {
		return
	}

	validChallenge, err := s.svc.Verify2FAChallenge(r.Context(), userID, challenge)
	if err != nil {
		serverErr(w, ErrChallengeVerifyFailed)
		return
	}
	if !validChallenge {
		logLoginFailed(s, r, userID, "invalid_challenge")
		unauthorized(w, ErrInvalidChallenge)
		return
	}

	var valid bool
	if req.BackupCode {
		valid, err = s.svc.VerifyBackupCode(r.Context(), userID, code)
	} else if strings.TrimSpace(req.FactorID) != "" {
		valid, err = s.svc.Verify2FAFactorCode(r.Context(), userID, strings.TrimSpace(req.FactorID), code)
	} else {
		valid, err = s.svc.Verify2FACode(r.Context(), userID, code)
	}
	if err != nil || !valid {
		logLoginFailed(s, r, userID, "invalid_code")
		unauthorized(w, ErrInvalidCode)
		return
	}
	_ = s.svc.Clear2FAChallenge(r.Context(), userID)

	sid, rt, _, err := s.svc.IssueRefreshSessionWithAuthMethods(r.Context(), userID, r.UserAgent(), nil, []string{"pwd", "otp", "mfa"})
	if err != nil {
		if errors.Is(err, authkit.ErrUserBanned) {
			logLoginFailed(s, r, userID, "user_banned")
			unauthorized(w, ErrUserBanned)
			return
		}
		serverErr(w, ErrSessionCreationFailed)
		return
	}

	ua := r.UserAgent()
	ip := remoteIP(r)
	uaPtr, ipPtr := &ua, &ip
	s.svc.LogSessionCreated(r.Context(), userID, "password_login_2fa", sid, ipPtr, uaPtr)

	usr, _ := s.svc.AdminGetUser(r.Context(), userID)
	emailForToken := ""
	if usr != nil && usr.Email != nil {
		emailForToken = *usr.Email
	}

	token, exp, err := s.svc.IssueAccessToken(r.Context(), userID, emailForToken, map[string]any{"sid": sid})
	if err != nil {
		if errors.Is(err, authkit.ErrUserBanned) {
			unauthorized(w, ErrUserBanned)
			return
		}
		serverErr(w, ErrTokenCreationFailed)
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"access_token":  token,
		"token_type":    "Bearer",
		"expires_in":    int64(time.Until(exp).Seconds()),
		"refresh_token": rt,
	})
}

func (s *Service) handleUser2FAChallengePOST(w http.ResponseWriter, r *http.Request) {
	if s.rateLimited(w, r, RL2FAVerify) {
		return
	}
	var req struct {
		UserID    string `json:"user_id"`
		Challenge string `json:"challenge"`
		FactorID  string `json:"factor_id"`
	}
	if err := decodeJSON(r, &req); err != nil {
		badRequest(w, ErrInvalidRequest)
		return
	}
	userID := strings.TrimSpace(req.UserID)
	challenge := strings.TrimSpace(req.Challenge)
	factorID := strings.TrimSpace(req.FactorID)
	if userID == "" || challenge == "" || factorID == "" {
		badRequest(w, ErrMissingFields)
		return
	}
	if s.rateLimitedByIdentifier(w, r, RL2FAVerify, userID) {
		return
	}
	validChallenge, err := s.svc.Verify2FAChallenge(r.Context(), userID, challenge)
	if err != nil {
		serverErr(w, ErrChallengeVerifyFailed)
		return
	}
	if !validChallenge {
		unauthorized(w, ErrInvalidChallenge)
		return
	}
	destination, method, factor, err := s.svc.Require2FAForLoginFactor(r.Context(), userID, factorID)
	if err != nil {
		if s.handleDeliveryError(w, r, "2fa_challenge", "send_2fa_code", err) {
			return
		}
		serverErr(w, ErrTwoFASendFailed)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"requires_2fa":    true,
		"method":          method,
		"verification_id": obfuscateVerificationID(destination),
		"factor": twoFactorFactorResponse{
			ID:          factor.ID,
			Method:      factor.Method,
			IsDefault:   factor.IsDefault,
			PhoneNumber: factor.PhoneNumber,
		},
	})
}
