package authhttp

import (
	"errors"
	"net/http"
	"strings"

	authkit "github.com/open-rails/authkit"
	"github.com/open-rails/authkit/embedded"
)

func (s *Service) handleUser2FAVerifyPOST(w http.ResponseWriter, r *http.Request) {
	var req struct {
		UserID     string `json:"user_id"`
		Code       string `json:"code"`
		Challenge  string `json:"challenge"`
		FactorID   string `json:"factor_id"`
		BackupCode bool   `json:"backup_code"`
	}
	if err := decodeJSON(r, &req); err != nil {
		badRequest(w, authkit.CodeInvalidRequest)
		return
	}

	userID := strings.TrimSpace(req.UserID)
	code := strings.TrimSpace(req.Code)
	challenge := strings.TrimSpace(req.Challenge)
	if userID == "" || code == "" || challenge == "" {
		badRequest(w, authkit.CodeMissingFields)
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
		serverErr(w, authkit.CodeChallengeVerifyFailed)
		return
	}
	if !validChallenge {
		logLoginFailed(s, r, userID, "invalid_challenge")
		unauthorized(w, authkit.CodeInvalidChallenge)
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
		unauthorized(w, authkit.CodeInvalidCode)
		return
	}
	_ = s.svc.Clear2FAChallenge(r.Context(), userID)

	// Create the refresh session AND mint its access token from a single user load +
	// MFA read (#227), recording the verified second factor via authMethods. The
	// banned gate still fires with authkit.CodeUserBanned; the ID-token email the old path
	// fetched (AdminGetUser) was ignored by MintAccessToken, so it's gone.
	sid, rt, token, exp, _, err := s.svc.IssueAuthenticatedSession(r.Context(), userID, r.UserAgent(), parseIP(remoteIP(r)), []string{"pwd", "otp", "mfa"}, nil)
	if err != nil {
		if errors.Is(err, authkit.ErrUserBanned) {
			logLoginFailed(s, r, userID, "user_banned")
			unauthorized(w, authkit.CodeUserBanned)
			return
		}
		serverErr(w, authkit.CodeSessionCreationFailed)
		return
	}

	ua := r.UserAgent()
	ip := remoteIP(r)
	uaPtr, ipPtr := &ua, &ip
	s.svc.LogSessionCreated(r.Context(), userID, "password_login_2fa", sid, ipPtr, uaPtr)

	s.writeTokenSet(w, r, http.StatusOK, authkit.NewTokenSet(token, rt, exp))
}

func (s *Service) handleUser2FAChallengePOST(w http.ResponseWriter, r *http.Request) {
	var req struct {
		UserID    string `json:"user_id"`
		Challenge string `json:"challenge"`
		FactorID  string `json:"factor_id"`
	}
	if err := decodeJSON(r, &req); err != nil {
		badRequest(w, authkit.CodeInvalidRequest)
		return
	}
	userID := strings.TrimSpace(req.UserID)
	challenge := strings.TrimSpace(req.Challenge)
	factorID := strings.TrimSpace(req.FactorID)
	if userID == "" || challenge == "" || factorID == "" {
		badRequest(w, authkit.CodeMissingFields)
		return
	}
	if s.rateLimitedByIdentifier(w, r, RL2FAVerify, userID) {
		return
	}
	validChallenge, err := s.svc.Verify2FAChallenge(r.Context(), userID, challenge)
	if err != nil {
		serverErr(w, authkit.CodeChallengeVerifyFailed)
		return
	}
	if !validChallenge {
		unauthorized(w, authkit.CodeInvalidChallenge)
		return
	}
	destination, method, factor, err := s.svc.Require2FAForLoginFactor(r.Context(), userID, factorID)
	if err != nil {
		writeError(w, err)
		return
	}
	sendErrData(w, http.StatusForbidden, authkit.CodeTwoFARequired, map[string]any{
		"method":          method,
		"verification_id": embedded.MaskDestination(destination),
		"factor": twoFactorFactorResponse{
			ID:          factor.ID,
			Method:      factor.Method,
			IsDefault:   factor.IsDefault,
			PhoneNumber: factor.PhoneNumber,
		},
	})
}
