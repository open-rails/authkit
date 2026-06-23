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

func (s *Service) handleUser2FAPOST(w http.ResponseWriter, r *http.Request) {
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
		Phone       string  `json:"phone,omitempty"`
		PhoneNumber *string `json:"phone_number"`
	}
	if err := decodeJSON(r, &req); err != nil {
		badRequest(w, ErrInvalidRequest)
		return
	}

	method := strings.ToLower(strings.TrimSpace(req.Method))
	if method != "email" && method != "sms" && method != "totp" {
		badRequest(w, ErrInvalidMethod)
		return
	}

	switch method {
	case "sms":
		phone := strings.TrimSpace(req.Phone)
		if req.PhoneNumber != nil {
			phone = strings.TrimSpace(*req.PhoneNumber)
		}
		if phone == "" {
			badRequest(w, ErrPhoneAndCodeRequired)
			return
		}
		if !strings.HasPrefix(phone, "+") {
			badRequest(w, ErrPhoneNumberMustBeE164)
			return
		}

		if strings.TrimSpace(req.Code) == "" {
			s.startPhone2FASetup(w, r, claims.UserID, phone)
			return
		}

		valid, err := s.svc.VerifyPhone2FASetupCode(r.Context(), claims.UserID, phone, req.Code)
		if err != nil || !valid {
			badRequest(w, ErrInvalidCode)
			return
		}
		req.PhoneNumber = &phone
	case "totp":
		if strings.TrimSpace(req.Code) == "" {
			if s.rateLimited(w, r, RL2FAStartTOTP) {
				return
			}
			secret, uri, err := s.svc.StartTOTPEnrollment(r.Context(), claims.UserID)
			if err != nil {
				serverErr(w, ErrEnableTwoFAFailed)
				return
			}
			writeJSON(w, http.StatusOK, map[string]any{
				"method":      "totp",
				"secret":      secret,
				"otpauth_uri": uri,
			})
			return
		}

		backupCodes, err := s.svc.EnableTOTP2FA(r.Context(), claims.UserID, req.Code)
		if err != nil {
			badRequest(w, ErrInvalidCode)
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{
			"enabled":      true,
			"method":       method,
			"backup_codes": backupCodes,
		})
		return
	}

	backupCodes, err := s.svc.Enable2FA(r.Context(), claims.UserID, method, req.PhoneNumber)
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

func (s *Service) startPhone2FASetup(w http.ResponseWriter, r *http.Request, userID, phone string) {
	if s.rateLimited(w, r, RL2FAStartPhone) {
		return
	}
	// Gate on real SMS deliverability up front (parity with signup / phone
	// verification / phone change) so an undeliverable sender fails fast instead
	// of stranding the user waiting for a code that will never arrive.
	if !s.svc.SMSAvailable() {
		serverErr(w, ErrPhoneTwoFAUnavailable)
		return
	}

	n, err := rand.Int(rand.Reader, big.NewInt(900000))
	if err != nil {
		serverErr(w, ErrSendCodeFailed)
		return
	}
	code := 100000 + int(n.Int64())
	codeStr := fmt.Sprintf("%06d", code)

	if err := s.svc.SendPhone2FASetupCode(r.Context(), userID, phone, codeStr); err != nil {
		if s.handleDeliveryError(w, r, "user_2fa_start_phone", "send_phone_2fa_setup", err) {
			return
		}
		serverErr(w, ErrSendCodeFailed)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "method": "sms"})
}

func (s *Service) handleUser2FADELETE(w http.ResponseWriter, r *http.Request) {
	if s.rateLimited(w, r, RL2FADisable) {
		return
	}
	claims, ok := ClaimsFromContext(r.Context())
	if !ok || claims.UserID == "" {
		unauthorized(w, ErrUnauthorized)
		return
	}
	if !s.requireFreshAuthOrPassword(w, r, claims, "") {
		return
	}

	if err := s.svc.Disable2FA(r.Context(), claims.UserID); err != nil {
		serverErr(w, ErrDisableTwoFAFailed)
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{"success": true})
}

func (s *Service) handleUser2FABackupCodesPOST(w http.ResponseWriter, r *http.Request) {
	if s.rateLimited(w, r, RL2FARegenerateCodes) {
		return
	}
	claims, ok := ClaimsFromContext(r.Context())
	if !ok || claims.UserID == "" {
		unauthorized(w, ErrUnauthorized)
		return
	}
	if !s.requireFreshAuthOrPassword(w, r, claims, "") {
		return
	}

	backupCodes, err := s.svc.RegenerateBackupCodes(r.Context(), claims.UserID)
	if err != nil {
		serverErr(w, ErrRegenerateCodesFailed)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"backup_codes": backupCodes})
}
