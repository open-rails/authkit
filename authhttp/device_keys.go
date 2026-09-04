package authhttp

import (
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"

	jwt "github.com/golang-jwt/jwt/v5"
	"github.com/open-rails/authkit"
	"github.com/open-rails/authkit/embedded"
	authcore "github.com/open-rails/authkit/internal/authcore"
	"github.com/open-rails/authkit/verify"
)

type deviceKeyResponse struct {
	ID        string    `json:"id"`
	Label     string    `json:"label,omitempty"`
	CreatedAt time.Time `json:"created_at"`
}

type deviceKeyListResponse struct {
	ID         string     `json:"id"`
	Label      string     `json:"label,omitempty"`
	CreatedAt  time.Time  `json:"created_at"`
	LastUsedAt *time.Time `json:"last_used_at,omitempty"`
	RevokedAt  *time.Time `json:"revoked_at,omitempty"`
	Current    bool       `json:"current"`
}

type deviceKeyTokenResponse struct {
	AccessToken string            `json:"access_token"`
	TokenType   string            `json:"token_type"`
	ExpiresAt   time.Time         `json:"expires_at"`
	DeviceKey   deviceKeyResponse `json:"device_key"`
}

func deviceKeyHTTPResponse(id, label string, createdAt time.Time) deviceKeyResponse {
	return deviceKeyResponse{ID: id, Label: label, CreatedAt: createdAt}
}

func (s *Service) handleDeviceKeyEnrollBeginPOST(w http.ResponseWriter, r *http.Request) {
	if s.rateLimited(w, r, RLDeviceKeyEnrollBegin) {
		return
	}
	var req struct {
		Email     string `json:"email"`
		PublicKey string `json:"public_key"`
		Label     string `json:"label,omitempty"`
	}
	if err := decodeJSON(r, &req); err != nil {
		badRequest(w, ErrInvalidRequest)
		return
	}
	email := embedded.NormalizeEmail(req.Email)
	if len(email) > 320 || embedded.ValidateEmail(email) != nil || len(strings.TrimSpace(req.PublicKey)) != 43 || len(strings.TrimSpace(req.Label)) > 128 {
		badRequest(w, ErrInvalidRequest)
		return
	}
	if s.rateLimitedByIdentifier(w, r, RLDeviceKeyEnrollBegin, email) ||
		s.rateLimitedByIdentifier(w, r, RLDeviceKeyEnrollBegin, strings.TrimSpace(req.PublicKey)) {
		return
	}
	result, err := s.svc.BeginDeviceKeyEnrollment(r.Context(), email, req.PublicKey, req.Label)
	if err != nil {
		switch {
		case errors.Is(err, authkit.ErrDeviceKeysDisabled):
			forbidden(w, ErrDeviceKeysDisabled)
		case errors.Is(err, authkit.ErrEmailSenderUnavailable), errors.Is(err, authkit.ErrEmailDeliveryFailed):
			serverErr(w, ErrEmailVerificationUnavailable)
		case embedded.ValidationErrorCode(err) != "", errors.Is(err, jwt.ErrTokenUnverifiable):
			badRequest(w, ErrInvalidRequest)
		default:
			s.logInternalError(r, "device_key_enroll_begin", "begin", "device_key_enroll_begin_failed", err)
			serverErr(w, ErrDatabaseError)
		}
		return
	}
	writeJSON(w, http.StatusAccepted, map[string]any{
		"enrollment_id": result.ID,
		"challenge":     result.Challenge,
		"expires_at":    result.ExpiresAt,
	})
}

func (s *Service) handleDeviceKeyEnrollFinishPOST(w http.ResponseWriter, r *http.Request) {
	if s.rateLimited(w, r, RLDeviceKeyEnrollFinish) {
		return
	}
	var req struct {
		EnrollmentID string `json:"enrollment_id"`
		Code         string `json:"code"`
		Signature    string `json:"signature"`
		SecondFactor string `json:"code_2fa"`
	}
	if err := decodeJSON(r, &req); err != nil {
		badRequest(w, ErrInvalidRequest)
		return
	}
	if len(strings.TrimSpace(req.EnrollmentID)) != 43 || len(strings.TrimSpace(req.Code)) != 6 || len(strings.TrimSpace(req.Signature)) != 86 || len(strings.TrimSpace(req.SecondFactor)) > 32 {
		badRequest(w, ErrInvalidRequest)
		return
	}
	if s.rateLimitedByIdentifier(w, r, RLDeviceKeyEnrollFinish, req.EnrollmentID) {
		return
	}
	result, err := s.svc.FinishDeviceKeyEnrollment(r.Context(), req.EnrollmentID, req.Code, req.Signature, req.SecondFactor)
	if err != nil {
		var secondFactor *authcore.DeviceKeySecondFactorRequired
		switch {
		case errors.As(err, &secondFactor):
			// Email code and key proof are valid; the ceremony stays live for a
			// retry that carries the second factor in code_2fa.
			sendErrData(w, http.StatusForbidden, ErrStepUpRequired, map[string]any{"method": secondFactor.Method, "param": "code_2fa"})
		case errors.Is(err, jwt.ErrTokenUnverifiable), errors.Is(err, jwt.ErrTokenInvalidClaims):
			s.svc.RecordFailedDeviceKeyEnrollment(r.Context(), req.EnrollmentID)
			badRequest(w, ErrInvalidOrExpiredCode)
		case errors.Is(err, authkit.ErrDeviceKeysDisabled):
			forbidden(w, ErrDeviceKeysDisabled)
		case errors.Is(err, authkit.ErrRegistrationDisabled):
			registrationDisabled(w)
		case errors.Is(err, authkit.ErrUserBanned):
			unauthorized(w, ErrInvalidCredentials)
		default:
			s.logInternalError(r, "device_key_enroll_finish", "finish", "device_key_enroll_finish_failed", err)
			serverErr(w, ErrDatabaseError)
		}
		return
	}
	writeJSON(w, http.StatusOK, deviceKeyTokenResponse{
		AccessToken: result.AccessToken,
		TokenType:   "Bearer",
		ExpiresAt:   result.ExpiresAt,
		DeviceKey:   deviceKeyHTTPResponse(result.DeviceKey.ID, result.DeviceKey.Label, result.DeviceKey.CreatedAt),
	})
}

func (s *Service) handleDeviceKeyLoginBeginPOST(w http.ResponseWriter, r *http.Request) {
	if s.rateLimited(w, r, RLDeviceKeyLoginBegin) {
		return
	}
	var req struct {
		DeviceKeyID string `json:"device_key_id"`
	}
	if err := decodeJSON(r, &req); err != nil {
		badRequest(w, ErrInvalidRequest)
		return
	}
	if len(strings.TrimSpace(req.DeviceKeyID)) != 36 {
		badRequest(w, ErrInvalidRequest)
		return
	}
	if s.rateLimitedByIdentifier(w, r, RLDeviceKeyLoginBegin, req.DeviceKeyID) {
		return
	}
	result, err := s.svc.BeginDeviceKeyLogin(r.Context(), req.DeviceKeyID)
	if err != nil {
		if errors.Is(err, authkit.ErrDeviceKeysDisabled) {
			forbidden(w, ErrDeviceKeysDisabled)
			return
		}
		if errors.Is(err, jwt.ErrTokenUnverifiable) {
			badRequest(w, ErrInvalidRequest)
			return
		}
		s.logInternalError(r, "device_key_login_begin", "begin", "device_key_login_begin_failed", err)
		serverErr(w, ErrDatabaseError)
		return
	}
	writeJSON(w, http.StatusAccepted, map[string]any{
		"challenge_id": result.ID,
		"challenge":    result.Challenge,
		"expires_at":   result.ExpiresAt,
	})
}

func (s *Service) handleDeviceKeyLoginFinishPOST(w http.ResponseWriter, r *http.Request) {
	if s.rateLimited(w, r, RLDeviceKeyLoginFinish) {
		return
	}
	var req struct {
		ChallengeID string `json:"challenge_id"`
		Signature   string `json:"signature"`
	}
	if err := decodeJSON(r, &req); err != nil {
		badRequest(w, ErrInvalidRequest)
		return
	}
	if len(strings.TrimSpace(req.ChallengeID)) != 43 || len(strings.TrimSpace(req.Signature)) != 86 {
		badRequest(w, ErrInvalidRequest)
		return
	}
	if s.rateLimitedByIdentifier(w, r, RLDeviceKeyLoginFinish, req.ChallengeID) {
		return
	}
	result, err := s.svc.FinishDeviceKeyLogin(r.Context(), req.ChallengeID, req.Signature)
	if err != nil {
		if errors.Is(err, authkit.ErrDeviceKeysDisabled) {
			forbidden(w, ErrDeviceKeysDisabled)
			return
		}
		if !errors.Is(err, jwt.ErrTokenUnverifiable) && !errors.Is(err, authkit.ErrUserBanned) {
			s.logInternalError(r, "device_key_login_finish", "finish", "device_key_login_finish_failed", err)
		}
		unauthorized(w, ErrInvalidCredentials)
		return
	}
	writeJSON(w, http.StatusOK, deviceKeyTokenResponse{
		AccessToken: result.AccessToken,
		TokenType:   "Bearer",
		ExpiresAt:   result.ExpiresAt,
		DeviceKey:   deviceKeyHTTPResponse(result.DeviceKey.ID, result.DeviceKey.Label, result.DeviceKey.CreatedAt),
	})
}

func deviceKeyCaller(r *http.Request) (verify.Claims, bool) {
	claims, ok := verify.ClaimsFromContext(r.Context())
	return claims, ok && claims.UserID != "" && claims.DeviceKeyID != "" && claims.HasAMR("device_key")
}

func (s *Service) handleDeviceKeysGET(w http.ResponseWriter, r *http.Request) {
	if s.rateLimited(w, r, RLDeviceKeysManage) {
		return
	}
	claims, ok := deviceKeyCaller(r)
	if !ok {
		unauthorized(w, ErrUnauthorized)
		return
	}
	keys, err := s.svc.ListDeviceKeys(r.Context(), claims.UserID, claims.DeviceKeyID)
	if err != nil {
		unauthorized(w, ErrUnauthorized)
		return
	}
	answer := make([]deviceKeyListResponse, 0, len(keys))
	for _, key := range keys {
		answer = append(answer, deviceKeyListResponse{
			ID: key.ID, Label: key.Label, CreatedAt: key.CreatedAt,
			LastUsedAt: key.LastUsedAt, RevokedAt: key.RevokedAt,
			Current: key.ID == claims.DeviceKeyID,
		})
	}
	writeJSON(w, http.StatusOK, map[string]any{"device_keys": answer})
}

func (s *Service) handleDeviceKeyDELETE(w http.ResponseWriter, r *http.Request) {
	if s.rateLimited(w, r, RLDeviceKeysManage) {
		return
	}
	claims, ok := deviceKeyCaller(r)
	if !ok {
		unauthorized(w, ErrUnauthorized)
		return
	}
	target := strings.TrimSpace(r.PathValue("id"))
	if len(target) != 36 {
		badRequest(w, ErrInvalidRequest)
		return
	}
	if err := s.svc.RevokeDeviceKey(r.Context(), claims.UserID, claims.DeviceKeyID, target); err != nil {
		unauthorized(w, ErrUnauthorized)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func (s *Service) handleDeviceKeysRevokeOthersPOST(w http.ResponseWriter, r *http.Request) {
	if s.rateLimited(w, r, RLDeviceKeysManage) {
		return
	}
	claims, ok := deviceKeyCaller(r)
	if !ok {
		unauthorized(w, ErrUnauthorized)
		return
	}
	// The enrollment finish token is the bounded recovery-root proof: it
	// carries both the device-key and verified-email authentication methods.
	if !claims.HasAMR("email") {
		forbidden(w, ErrForbidden)
		return
	}
	if r.Body != nil && r.Body != http.NoBody && r.ContentLength != 0 {
		var empty map[string]json.RawMessage
		if err := decodeJSON(r, &empty); err != nil || len(empty) != 0 {
			badRequest(w, ErrInvalidRequest)
			return
		}
	}
	if err := s.svc.RevokeOtherDeviceKeys(r.Context(), claims.UserID, claims.DeviceKeyID); err != nil {
		unauthorized(w, ErrUnauthorized)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}
