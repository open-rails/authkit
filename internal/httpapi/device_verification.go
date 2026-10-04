package httpapi

import (
	"errors"
	"net/http"
	"strings"

	jwt "github.com/golang-jwt/jwt/v5"

	"github.com/open-rails/authkit/internal/authflow"
	"github.com/open-rails/authkit/internal/contact"
	"github.com/open-rails/authkit/internal/errmodel"
)

// A new device past Config.SignIn.NewDevicesPerAccount finishes signing in
// with the code its sign-in sent to the account's proven email or phone.

func (s *Service) handleDeviceVerificationSendPOST(w http.ResponseWriter, r *http.Request) {
	var req DeviceVerificationSendRequest
	if err := decodeJSON(r, &req); err != nil {
		fail(w, errmodel.CodeInvalidRequest)
		return
	}
	userID, challenge := strings.TrimSpace(req.UserID), strings.TrimSpace(req.Challenge)
	channel := strings.ToLower(strings.TrimSpace(req.Channel))
	if userID == "" || challenge == "" {
		fail(w, errmodel.CodeMissingFields)
		return
	}
	if channel != "" && channel != "email" && channel != "sms" {
		fail(w, errmodel.CodeInvalidRequest, errmodel.WithParam("channel"))
		return
	}
	// Keyed by the proof, like the confirm route; the engine also caps the
	// codes one account is sent an hour.
	if s.rateLimitedByIdentifier(w, r, RLStepUpCodeSend, loginProofKey(userID, challenge)) {
		return
	}
	ch, err := s.svc.SendDeviceVerification(r.Context(), userID, challenge, channel)
	if err != nil {
		writeError(w, deviceChallengeError(err))
		return
	}
	writeAuthResult(w, AuthResult{Status: AuthDeviceVerificationRequired, DeviceVerification: deviceVerificationStep(userID, ch)})
}

func (s *Service) handleDeviceVerificationConfirmPOST(w http.ResponseWriter, r *http.Request) {
	var req DeviceVerificationConfirmRequest
	if err := decodeJSON(r, &req); err != nil {
		fail(w, errmodel.CodeInvalidRequest)
		return
	}
	userID, challenge, code := strings.TrimSpace(req.UserID), strings.TrimSpace(req.Challenge), strings.TrimSpace(req.Code)
	if userID == "" || challenge == "" || code == "" {
		fail(w, errmodel.CodeMissingFields)
		return
	}
	// Keyed by the proof, like /2fa/verify: a stranger who knows only the
	// user id cannot spend the holder's budget.
	if s.rateLimitedByIdentifier(w, r, RLStepUpCode, loginProofKey(userID, challenge)) {
		return
	}
	out, err := s.svc.ConfirmDeviceVerification(r.Context(), authflow.DeviceVerificationInput{UserID: userID, Challenge: challenge, Code: code, UserAgent: r.UserAgent(), IP: s.requestIP(r)})
	switch {
	case err == nil:
		s.writeAuthResult(w, r, out, authExtras{})
	case errors.Is(err, errmodel.ErrInvalidCode), errors.Is(err, errmodel.ErrCodeExpired):
		logLoginFailed(s, r, userID, "invalid_device_code")
		fail(w, codeRejection(err))
	default:
		writeError(w, deviceChallengeError(err))
	}
}

// deviceChallengeError: a missing, expired or spent challenge is
// invalid_challenge; every other refusal keeps its own code.
func deviceChallengeError(err error) error {
	if errors.Is(err, jwt.ErrTokenUnverifiable) {
		return errmodel.E(errmodel.CodeInvalidChallenge)
	}
	return err
}

// deviceVerificationStep is a device challenge on the wire, its destination
// masked.
func deviceVerificationStep(userID string, ch *authflow.DeviceChallenge) *DeviceVerificationStep {
	channels := ch.Channels
	if channels == nil {
		channels = []string{}
	}
	return &DeviceVerificationStep{UserID: userID, Challenge: ch.Challenge, Channel: ch.Channel, Destination: contact.MaskDestination(ch.Destination), Channels: channels}
}
