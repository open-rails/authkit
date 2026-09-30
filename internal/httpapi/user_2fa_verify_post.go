package httpapi

import (
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"strings"

	"github.com/open-rails/authkit/internal/authflow"
	"github.com/open-rails/authkit/internal/errmodel"
)

func (s *Service) handleUser2FAVerifyPOST(w http.ResponseWriter, r *http.Request) {
	var req TwoFactorVerifyRequest
	if err := decodeJSON(r, &req); err != nil {
		fail(w, errmodel.CodeInvalidRequest)
		return
	}

	userID := strings.TrimSpace(req.UserID)
	code := strings.TrimSpace(req.Code)
	challenge := strings.TrimSpace(req.Challenge)
	if userID == "" || code == "" || challenge == "" {
		fail(w, errmodel.CodeMissingFields)
		return
	}

	// The engine bounds guesses per first-factor proof and per account. This
	// bucket is keyed by the proof too: a stranger who knows only user_id cannot
	// spend the real holder's budget (ak#392).
	if s.rateLimitedByIdentifier(w, r, RL2FAVerify, loginProofKey(userID, challenge)) {
		return
	}

	out, err := s.svc.CompleteLoginChallenge(r.Context(), authflow.LoginChallengeInput{UserID: userID, Challenge: challenge, FactorID: strings.TrimSpace(req.FactorID), Code: code, BackupCode: req.BackupCode, UserAgent: r.UserAgent(), IP: s.requestIP(r)})
	if err != nil {
		logLoginFailed(s, r, userID, "invalid_challenge_or_code")
		fail(w, codeRejection(err))
		return
	}
	s.writeAuthResult(w, r, out, authExtras{})
}

func (s *Service) handleUser2FAChallengePOST(w http.ResponseWriter, r *http.Request) {
	var req TwoFactorChallengeRequest
	if err := decodeJSON(r, &req); err != nil {
		fail(w, errmodel.CodeInvalidRequest)
		return
	}
	userID := strings.TrimSpace(req.UserID)
	challenge := strings.TrimSpace(req.Challenge)
	factorID := strings.TrimSpace(req.FactorID)
	if userID == "" || challenge == "" || factorID == "" {
		fail(w, errmodel.CodeMissingFields)
		return
	}
	if s.rateLimitedByIdentifier(w, r, RL2FAVerify, loginProofKey(userID, challenge)) {
		return
	}
	// The sign-in stays where it was, its code now at the chosen factor.
	ch, err := s.svc.ResendLoginChallenge(r.Context(), userID, challenge, factorID)
	if err != nil {
		fail(w, errmodel.CodeInvalidChallenge)
		return
	}
	writeAuthResult(w, AuthResult{Status: AuthSecondFactorRequired, SecondFactor: secondFactorStep(userID, ch)})
}

func loginProofKey(userID, challenge string) string {
	sum := sha256.Sum256([]byte(challenge))
	return userID + ":" + hex.EncodeToString(sum[:16])
}
