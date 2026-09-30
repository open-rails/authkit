package httpapi

import (
	"errors"
	"net/http"
	"strings"

	"github.com/open-rails/authkit/internal/errmodel"
	"github.com/open-rails/authkit/verify"
)

// Step-up by a code to a proven address, the linked wallet or a passkey: each
// is begun and finished by the same session, and answers its fresh
// AuthResult.

// handleStepUpCodeSendPOST sends a step-up code to the account's proven email
// or phone.
func (s *Service) handleStepUpCodeSendPOST(w http.ResponseWriter, r *http.Request) {
	claims, ok := stepUpCaller(w, r)
	if !ok {
		return
	}
	var body StepUpCodeSendRequest
	if err := decodeJSON(r, &body); err != nil {
		fail(w, errmodel.CodeInvalidRequest)
		return
	}
	channel := strings.ToLower(strings.TrimSpace(body.Channel))
	if channel != "email" && channel != "sms" {
		fail(w, errmodel.CodeInvalidRequest, errmodel.WithParam("channel"))
		return
	}
	if s.rateLimitedByIdentifier(w, r, RLStepUpCodeSend, claims.UserID) {
		return
	}
	if err := s.svc.SendStepUpCode(r.Context(), claims.UserID, claims.SessionID, channel); err != nil {
		writeError(w, err)
		return
	}
	accepted(w)
}

// handleStepUpCodePOST re-authenticates the session with the code
// /me/step-up/code/send sent it.
func (s *Service) handleStepUpCodePOST(w http.ResponseWriter, r *http.Request) {
	claims, ok := stepUpCaller(w, r)
	if !ok || s.rateLimitedByIdentifier(w, r, RLStepUpCode, claims.UserID) {
		return
	}
	var body CodeRequest
	if err := decodeJSON(r, &body); err != nil || strings.TrimSpace(body.Code) == "" {
		fail(w, errmodel.CodeInvalidRequest, errmodel.WithParam("code"))
		return
	}
	s.finishStepUp(w, r, claims, s.svc.StepUpWithCode(r.Context(), claims.UserID, claims.SessionID, strings.TrimSpace(body.Code)))
}

// handleSolanaStepUpChallengePOST answers the SIWS message the linked wallet
// signs to step up.
func (s *Service) handleSolanaStepUpChallengePOST(w http.ResponseWriter, r *http.Request) {
	claims, ok := stepUpCaller(w, r)
	if !ok || !noBody(w, r) {
		return
	}
	domain := siwsDomain(s.cfg.Frontend.BaseURL, s.cfg.Token.Issuer)
	if domain == "" {
		serverErr(w, "challenge_failed", errors.New("authkit: no SIWS domain: set Frontend.BaseURL or a URL Token.Issuer"))
		return
	}
	input, err := s.svc.BeginSolanaStepUp(r.Context(), claims.UserID, claims.SessionID, domain)
	if err != nil {
		writeError(w, err)
		return
	}
	writeSolanaChallenge(w, input)
}

func (s *Service) handleSolanaStepUpPOST(w http.ResponseWriter, r *http.Request) {
	claims, ok := stepUpCaller(w, r)
	if !ok {
		return
	}
	output, ok := decodeSIWSOutput(w, r)
	if !ok {
		return
	}
	s.finishStepUp(w, r, claims, s.svc.StepUpWithSolana(r.Context(), claims.UserID, claims.SessionID, output))
}

// handlePasskeyStepUpBeginPOST answers the assertion options for the
// account's passkeys.
func (s *Service) handlePasskeyStepUpBeginPOST(w http.ResponseWriter, r *http.Request) {
	claims, ok := stepUpCaller(w, r)
	if !ok || !noBody(w, r) {
		return
	}
	assertion, err := s.svc.BeginPasskeyStepUp(r.Context(), claims.UserID, claims.SessionID)
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, assertion)
}

func (s *Service) handlePasskeyStepUpPOST(w http.ResponseWriter, r *http.Request) {
	claims, ok := stepUpCaller(w, r)
	if !ok {
		return
	}
	body, err := readSmallBody(r)
	if err != nil {
		fail(w, errmodel.CodeInvalidRequest)
		return
	}
	s.finishStepUp(w, r, claims, s.svc.StepUpWithPasskey(r.Context(), claims.UserID, claims.SessionID, body))
}

// finishStepUp answers a step-up's outcome: its rejection, or the session's
// fresh AuthResult.
func (s *Service) finishStepUp(w http.ResponseWriter, r *http.Request, claims verify.Claims, err error) {
	if err != nil {
		writeError(w, err)
		return
	}
	s.writeFresh(w, r, claims.UserID, claims.SessionID)
}

// noBody refuses a request body other than none or {}.
func noBody(w http.ResponseWriter, r *http.Request) bool {
	if err := decodeOptionalJSON(r, &struct{}{}); err != nil {
		fail(w, errmodel.CodeInvalidRequest)
		return false
	}
	return true
}
