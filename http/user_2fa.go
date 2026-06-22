package authhttp

import (
	"crypto/rand"
	"fmt"
	"math/big"
	"net/http"
	"strings"
)

type twoFactorStatusResponse struct {
	Enabled     bool    `json:"enabled"`
	Method      string  `json:"method"`
	PhoneNumber *string `json:"phone_number,omitempty"`
}

func (s *Service) handleUser2FAStatusGET(w http.ResponseWriter, r *http.Request) {
	if s.rateLimited(w, r, RLUserMe) {
		return
	}
	claims, ok := ClaimsFromContext(r.Context())
	if !ok || claims.UserID == "" {
		unauthorized(w, ErrUnauthorized)
		return
	}

	settings, err := s.svc.Get2FASettings(r.Context(), claims.UserID)
	if err != nil {
		writeJSON(w, http.StatusOK, twoFactorStatusResponse{Enabled: false, Method: "email"})
		return
	}

	writeJSON(w, http.StatusOK, twoFactorStatusResponse{
		Enabled:     settings.Enabled,
		Method:      settings.Method,
		PhoneNumber: settings.PhoneNumber,
	})
}

func (s *Service) handleUser2FAStartPhonePOST(w http.ResponseWriter, r *http.Request) {
	if s.rateLimited(w, r, RL2FAStartPhone) {
		return
	}
	claims, ok := ClaimsFromContext(r.Context())
	if !ok || claims.UserID == "" {
		unauthorized(w, ErrUnauthorized)
		return
	}

	var req struct {
		Phone string `json:"phone"`
	}
	if err := decodeJSON(r, &req); err != nil || strings.TrimSpace(req.Phone) == "" {
		badRequest(w, ErrInvalidRequest)
		return
	}

	phoneNum := strings.TrimSpace(req.Phone)
	if !strings.HasPrefix(phoneNum, "+") {
		badRequest(w, ErrPhoneNumberMustBeE164)
		return
	}

	// Gate on real SMS deliverability up front (parity with signup / phone
	// verification / phone change) so an undeliverable sender fails fast instead
	// of stranding the user waiting for a code that will never arrive.
	if !s.svc.SMSAvailable() {
		serverErr(w, ErrPhoneTwoFAUnavailable)
		return
	}

	// Generate random 6-digit code.
	n, err := rand.Int(rand.Reader, big.NewInt(900000))
	if err != nil {
		serverErr(w, ErrSendCodeFailed)
		return
	}
	code := 100000 + int(n.Int64())
	codeStr := fmt.Sprintf("%06d", code)

	if err := s.svc.SendPhone2FASetupCode(r.Context(), claims.UserID, req.Phone, codeStr); err != nil {
		if s.handleDeliveryError(w, r, "user_2fa_start_phone", "send_phone_2fa_setup", err) {
			return
		}
		serverErr(w, ErrSendCodeFailed)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func (s *Service) handleUser2FAEnablePOST(w http.ResponseWriter, r *http.Request) {
	if s.rateLimited(w, r, RL2FAEnable) {
		return
	}
	claims, ok := ClaimsFromContext(r.Context())
	if !ok || claims.UserID == "" {
		unauthorized(w, ErrUnauthorized)
		return
	}

	var req struct {
		Method      string  `json:"method"`
		Code        string  `json:"code,omitempty"`
		PhoneNumber *string `json:"phone_number"`
	}
	if err := decodeJSON(r, &req); err != nil {
		badRequest(w, ErrInvalidRequest)
		return
	}

	method := strings.ToLower(strings.TrimSpace(req.Method))
	if method != "email" && method != "sms" {
		badRequest(w, ErrInvalidMethod)
		return
	}

	if method == "sms" {
		if req.PhoneNumber == nil || strings.TrimSpace(*req.PhoneNumber) == "" || strings.TrimSpace(req.Code) == "" {
			badRequest(w, ErrPhoneAndCodeRequired)
			return
		}
		phoneNum := strings.TrimSpace(*req.PhoneNumber)
		if !strings.HasPrefix(phoneNum, "+") {
			badRequest(w, ErrPhoneNumberMustBeE164)
			return
		}

		valid, err := s.svc.VerifyPhone2FASetupCode(r.Context(), claims.UserID, *req.PhoneNumber, req.Code)
		if err != nil || !valid {
			badRequest(w, ErrInvalidCode)
			return
		}
	}

	backupCodes, err := s.svc.Enable2FA(r.Context(), claims.UserID, req.Method, req.PhoneNumber)
	if err != nil {
		serverErr(w, ErrEnableTwoFAFailed)
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"enabled":      true,
		"method":       method,
		"backup_codes": backupCodes,
	})
}

func (s *Service) handleUser2FADisablePOST(w http.ResponseWriter, r *http.Request) {
	if s.rateLimited(w, r, RL2FADisable) {
		return
	}
	claims, ok := ClaimsFromContext(r.Context())
	if !ok || claims.UserID == "" {
		unauthorized(w, ErrUnauthorized)
		return
	}

	if err := s.svc.Disable2FA(r.Context(), claims.UserID); err != nil {
		serverErr(w, ErrDisableTwoFAFailed)
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{"success": true})
}

func (s *Service) handleUser2FARegenerateCodesPOST(w http.ResponseWriter, r *http.Request) {
	if s.rateLimited(w, r, RL2FARegenerateCodes) {
		return
	}
	claims, ok := ClaimsFromContext(r.Context())
	if !ok || claims.UserID == "" {
		unauthorized(w, ErrUnauthorized)
		return
	}

	backupCodes, err := s.svc.RegenerateBackupCodes(r.Context(), claims.UserID)
	if err != nil {
		serverErr(w, ErrRegenerateCodesFailed)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"backup_codes": backupCodes})
}
