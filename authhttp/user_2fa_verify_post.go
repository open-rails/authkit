package authhttp

import (
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

	out, err := s.svc.CompleteLoginChallenge(r.Context(), embedded.LoginChallengeInput{UserID: userID, Challenge: challenge, FactorID: strings.TrimSpace(req.FactorID), Code: code, BackupCode: req.BackupCode, UserAgent: r.UserAgent(), IP: s.requestIP(r)})
	if err != nil {
		logLoginFailed(s, r, userID, "invalid_challenge_or_code")
		unauthorized(w, authkit.CodeInvalidCode)
		return
	}
	if s.writeLoginContinuation(w, r, out, nil) {
		return
	}
	s.writeTokenSet(w, r, http.StatusOK, out.Session.TokenSet())
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
	out, err := s.svc.ResendLoginChallenge(r.Context(), userID, challenge, factorID)
	if err != nil {
		unauthorized(w, authkit.CodeInvalidChallenge)
		return
	}
	sendErrData(w, http.StatusForbidden, authkit.CodeTwoFARequired, loginChallengeMetadata(userID, out))
}
