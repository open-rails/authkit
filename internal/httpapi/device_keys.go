package httpapi

import (
	"encoding/json"
	"errors"
	"net/http"
	"strings"

	jwt "github.com/golang-jwt/jwt/v5"
	"github.com/open-rails/authkit/devicekey"
	"github.com/open-rails/authkit/iam"
	"github.com/open-rails/authkit/internal/authflow"
	"github.com/open-rails/authkit/internal/contact"
	"github.com/open-rails/authkit/internal/errmodel"
	"github.com/open-rails/authkit/verify"
)

// deviceKeyTokenResponse is a device key's sign-in; the key is the token's own.
type deviceKeyTokenResponse struct {
	TokenSet  iam.TokenSet  `json:"token_set"`
	DeviceKey devicekey.Key `json:"device_key"`
}

func deviceKeyWire(key authflow.DeviceKey, current bool) devicekey.Key {
	return devicekey.Key{ID: key.ID, Label: key.Label, CreatedAt: key.CreatedAt, LastUsedAt: key.LastUsedAt, RevokedAt: key.RevokedAt, Current: current}
}

func deviceKeyTokenHTTPResponse(result authflow.DeviceKeyAuthResult) deviceKeyTokenResponse {
	return deviceKeyTokenResponse{
		TokenSet:  iam.NewTokenSet(result.AccessToken, "", result.ExpiresAt),
		DeviceKey: deviceKeyWire(result.DeviceKey, true),
	}
}

func (s *Service) handleDeviceKeyEnrollBeginPOST(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Email     string `json:"email"`
		PublicKey string `json:"public_key"`
		Label     string `json:"label,omitempty"`
	}
	if err := decodeJSON(r, &req); err != nil {
		fail(w, errmodel.CodeInvalidRequest)
		return
	}
	email := contact.NormalizeEmail(req.Email)
	if len(email) > 320 || contact.ValidateEmail(email) != nil || len(strings.TrimSpace(req.PublicKey)) != 43 || len(strings.TrimSpace(req.Label)) > 128 {
		fail(w, errmodel.CodeInvalidRequest)
		return
	}
	if s.rateLimitedByIdentifier(w, r, RLDeviceKeyEnrollBegin, email) ||
		s.rateLimitedByIdentifier(w, r, RLDeviceKeyEnrollBegin, strings.TrimSpace(req.PublicKey)) {
		return
	}
	result, err := s.svc.BeginDeviceKeyEnrollment(r.Context(), email, req.PublicKey, req.Label)
	if err != nil {
		if errors.Is(err, jwt.ErrTokenUnverifiable) {
			fail(w, errmodel.CodeInvalidRequest)
			return
		}
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusAccepted, map[string]any{
		"enrollment_id": result.ID,
		"challenge":     result.Challenge,
		"expires_at":    result.ExpiresAt,
	})
}

func (s *Service) handleDeviceKeyEnrollFinishPOST(w http.ResponseWriter, r *http.Request) {
	var req struct {
		EnrollmentID string `json:"enrollment_id"`
		Code         string `json:"code"`
		Signature    string `json:"signature"`
		SecondFactor string `json:"code_2fa"`
	}
	if err := decodeJSON(r, &req); err != nil {
		fail(w, errmodel.CodeInvalidRequest)
		return
	}
	if len(strings.TrimSpace(req.EnrollmentID)) != 43 || len(strings.TrimSpace(req.Code)) != 6 || len(strings.TrimSpace(req.Signature)) != 86 || len(strings.TrimSpace(req.SecondFactor)) > 32 {
		fail(w, errmodel.CodeInvalidRequest)
		return
	}
	if s.rateLimitedByIdentifier(w, r, RLDeviceKeyEnrollFinish, req.EnrollmentID) {
		return
	}
	result, err := s.svc.FinishDeviceKeyEnrollment(r.Context(), req.EnrollmentID, req.Code, req.Signature, req.SecondFactor)
	if err != nil {
		var secondFactor *authflow.DeviceKeySecondFactorRequired
		switch {
		case errors.As(err, &secondFactor):
			// Email code and key proof are valid; the ceremony stays live for a
			// retry that carries the second factor in code_2fa.
			fail(w, errmodel.CodeStepUpRequired, errmodel.WithMetadata(map[string]any{"method": secondFactor.Method, "param": "code_2fa"}))
		case errors.Is(err, jwt.ErrTokenUnverifiable), errors.Is(err, jwt.ErrTokenInvalidClaims):
			s.svc.RecordFailedDeviceKeyEnrollment(r.Context(), req.EnrollmentID)
			fail(w, errmodel.CodeInvalidCode)
		default:
			writeError(w, remap(err, map[error]errmodel.Code{errmodel.ErrUserBanned: errmodel.CodeInvalidCredentials}))
		}
		return
	}
	writeJSON(w, http.StatusOK, deviceKeyTokenHTTPResponse(result))
}

func (s *Service) handleDeviceKeyLoginBeginPOST(w http.ResponseWriter, r *http.Request) {
	var req struct {
		DeviceKeyID string `json:"device_key_id"`
	}
	if err := decodeJSON(r, &req); err != nil {
		fail(w, errmodel.CodeInvalidRequest)
		return
	}
	if len(strings.TrimSpace(req.DeviceKeyID)) != 36 {
		fail(w, errmodel.CodeInvalidRequest)
		return
	}
	if s.rateLimitedByIdentifier(w, r, RLDeviceKeyLoginBegin, req.DeviceKeyID) {
		return
	}
	result, err := s.svc.BeginDeviceKeyLogin(r.Context(), req.DeviceKeyID)
	if err != nil {
		if errors.Is(err, jwt.ErrTokenUnverifiable) {
			fail(w, errmodel.CodeInvalidRequest)
			return
		}
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusAccepted, map[string]any{
		"challenge_id": result.ID,
		"challenge":    result.Challenge,
		"expires_at":   result.ExpiresAt,
	})
}

func (s *Service) handleDeviceKeyLoginFinishPOST(w http.ResponseWriter, r *http.Request) {
	var req struct {
		ChallengeID string `json:"challenge_id"`
		Signature   string `json:"signature"`
	}
	if err := decodeJSON(r, &req); err != nil {
		fail(w, errmodel.CodeInvalidRequest)
		return
	}
	if len(strings.TrimSpace(req.ChallengeID)) != 43 || len(strings.TrimSpace(req.Signature)) != 86 {
		fail(w, errmodel.CodeInvalidRequest)
		return
	}
	if s.rateLimitedByIdentifier(w, r, RLDeviceKeyLoginFinish, req.ChallengeID) {
		return
	}
	result, err := s.svc.FinishDeviceKeyLogin(r.Context(), req.ChallengeID, req.Signature)
	if err != nil {
		if errors.Is(err, iam.ErrDeviceKeysDisabled) {
			fail(w, errmodel.CodeDeviceKeysDisabled)
			return
		}
		// The key signed the challenge, but the account needs a second factor
		// the key never proved: re-enroll it with code_2fa, or enroll a factor.
		if errors.Is(err, errmodel.E(errmodel.CodeTwoFARequired)) || errors.Is(err, iam.ErrTwoFAEnrollmentRequired) {
			writeError(w, err)
			return
		}
		if !errors.Is(err, jwt.ErrTokenUnverifiable) && !errors.Is(err, errmodel.ErrUserBanned) {
			s.logInternalError(r, "device_key_login_finish", "finish", "device_key_login_finish_failed", err)
		}
		fail(w, errmodel.CodeInvalidCredentials)
		return
	}
	writeJSON(w, http.StatusOK, deviceKeyTokenHTTPResponse(result))
}

func deviceKeyCaller(r *http.Request) (verify.Claims, bool) {
	claims, ok := verify.ClaimsFromContext(r.Context())
	return claims, ok && claims.UserID != "" && claims.DeviceKeyID != "" && claims.HasAMR("device_key")
}

func (s *Service) handleDeviceKeysGET(w http.ResponseWriter, r *http.Request) {
	claims, ok := deviceKeyCaller(r)
	if !ok {
		fail(w, errmodel.CodeUnauthenticated)
		return
	}
	keys, err := s.svc.ListDeviceKeys(r.Context(), claims.UserID, claims.DeviceKeyID)
	if err != nil {
		fail(w, errmodel.CodeUnauthenticated)
		return
	}
	answer := make([]devicekey.Key, 0, len(keys))
	for _, key := range keys {
		answer = append(answer, deviceKeyWire(key, key.ID == claims.DeviceKeyID))
	}
	writeList(w, answer, "")
}

func (s *Service) handleDeviceKeyDELETE(w http.ResponseWriter, r *http.Request) {
	claims, ok := deviceKeyCaller(r)
	if !ok {
		fail(w, errmodel.CodeUnauthenticated)
		return
	}
	target := strings.TrimSpace(r.PathValue("id"))
	if len(target) != 36 {
		fail(w, errmodel.CodeInvalidRequest)
		return
	}
	if err := s.svc.RevokeDeviceKey(r.Context(), claims.UserID, claims.DeviceKeyID, target); err != nil {
		fail(w, errmodel.CodeUnauthenticated)
		return
	}
	noContent(w)
}

func (s *Service) handleDeviceKeysRevokeOthersPOST(w http.ResponseWriter, r *http.Request) {
	claims, ok := deviceKeyCaller(r)
	if !ok {
		fail(w, errmodel.CodeUnauthenticated)
		return
	}
	// The enrollment finish token is the bounded recovery-root proof: it
	// carries both the device-key and verified-email authentication methods.
	if !claims.HasAMR("email") {
		fail(w, errmodel.CodeForbidden)
		return
	}
	if r.Body != nil && r.Body != http.NoBody && r.ContentLength != 0 {
		var empty map[string]json.RawMessage
		if err := decodeJSON(r, &empty); err != nil || len(empty) != 0 {
			fail(w, errmodel.CodeInvalidRequest)
			return
		}
	}
	if err := s.svc.RevokeOtherDeviceKeys(r.Context(), claims.UserID, claims.DeviceKeyID); err != nil {
		fail(w, errmodel.CodeUnauthenticated)
		return
	}
	noContent(w)
}
