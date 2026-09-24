package authhttp

import (
	"crypto/sha256"
	"encoding/hex"
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

	// The engine bounds guesses per first-factor proof and per account. This
	// bucket is keyed by the proof too: a stranger who knows only user_id cannot
	// spend the real holder's budget (ak#392).
	if s.rateLimitedByIdentifier(w, r, RL2FAVerify, loginProofKey(userID, challenge)) {
		return
	}

	out, err := s.svc.CompleteLoginChallenge(r.Context(), embedded.LoginChallengeInput{UserID: userID, Challenge: challenge, FactorID: strings.TrimSpace(req.FactorID), Code: code, BackupCode: req.BackupCode, UserAgent: r.UserAgent(), IP: s.requestIP(r)})
	if err != nil {
		logLoginFailed(s, r, userID, "invalid_challenge_or_code")
		unauthorized(w, codeRejection(err))
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
	if s.rateLimitedByIdentifier(w, r, RL2FAVerify, loginProofKey(userID, challenge)) {
		return
	}
	out, err := s.svc.ResendLoginChallenge(r.Context(), userID, challenge, factorID)
	if err != nil {
		unauthorized(w, authkit.CodeInvalidChallenge)
		return
	}
	sendErrData(w, http.StatusForbidden, authkit.CodeTwoFARequired, loginChallengeMetadata(userID, out))
}

func loginProofKey(userID, challenge string) string {
	sum := sha256.Sum256([]byte(challenge))
	return userID + ":" + hex.EncodeToString(sum[:16])
}
