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
	if !s.allow(r, RLUserMe) {
		tooMany(w)
		return
	}
	claims, ok := ClaimsFromContext(r.Context())
	if !ok || claims.UserID == "" {
		unauthorized(w, "unauthorized")
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
	if !s.allow(r, RL2FAStartPhone) {
		tooMany(w)
		return
	}
	claims, ok := ClaimsFromContext(r.Context())
	if !ok || claims.UserID == "" {
		unauthorized(w, "unauthorized")
		return
	}

	var req struct {
		Phone string `json:"phone"`
	}
	if err := decodeJSON(r, &req); err != nil || strings.TrimSpace(req.Phone) == "" {
		badRequest(w, "invalid_request")
		return
	}

	phoneNum := strings.TrimSpace(req.Phone)
	if !strings.HasPrefix(phoneNum, "+") {
		badRequest(w, "phone_number_must_be_e164")
		return
	}

	// Generate random 6-digit code.
	n, err := rand.Int(rand.Reader, big.NewInt(900000))
	if err != nil {
		serverErr(w, "send_code_failed")
		return
	}
	code := 100000 + int(n.Int64())
	codeStr := fmt.Sprintf("%06d", code)

	if err := s.svc.SendPhone2FASetupCode(r.Context(), claims.UserID, req.Phone, codeStr); err != nil {
		serverErr(w, "send_code_failed")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func (s *Service) handleUser2FAEnablePOST(w http.ResponseWriter, r *http.Request) {
	if !s.allow(r, RL2FAEnable) {
		tooMany(w)
		return
	}
	claims, ok := ClaimsFromContext(r.Context())
	if !ok || claims.UserID == "" {
		unauthorized(w, "unauthorized")
		return
	}

	var req struct {
		Method      string  `json:"method"`
		Code        string  `json:"code,omitempty"`
		PhoneNumber *string `json:"phone_number"`
	}
	if err := decodeJSON(r, &req); err != nil {
		badRequest(w, "invalid_request")
		return
	}

	method := strings.ToLower(strings.TrimSpace(req.Method))
	if method != "email" && method != "sms" {
		badRequest(w, "invalid_method")
		return
	}

	if method == "sms" {
		if req.PhoneNumber == nil || strings.TrimSpace(*req.PhoneNumber) == "" || strings.TrimSpace(req.Code) == "" {
			badRequest(w, "phone_and_code_required")
			return
		}
		phoneNum := strings.TrimSpace(*req.PhoneNumber)
		if !strings.HasPrefix(phoneNum, "+") {
			badRequest(w, "phone_number_must_be_e164")
			return
		}

		valid, err := s.svc.VerifyPhone2FASetupCode(r.Context(), claims.UserID, *req.PhoneNumber, req.Code)
		if err != nil || !valid {
			unauthorized(w, "invalid_code")
			return
		}
	}

	backupCodes, err := s.svc.Enable2FA(r.Context(), claims.UserID, req.Method, req.PhoneNumber)
	if err != nil {
		serverErr(w, "enable_2fa_failed")
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"enabled":      true,
		"method":       method,
		"backup_codes": backupCodes,
	})
}

func (s *Service) handleUser2FADisablePOST(w http.ResponseWriter, r *http.Request) {
	if !s.allow(r, RL2FADisable) {
		tooMany(w)
		return
	}
	claims, ok := ClaimsFromContext(r.Context())
	if !ok || claims.UserID == "" {
		unauthorized(w, "unauthorized")
		return
	}

	if err := s.svc.Disable2FA(r.Context(), claims.UserID); err != nil {
		serverErr(w, "disable_2fa_failed")
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{"success": true})
}

func (s *Service) handleUser2FARegenerateCodesPOST(w http.ResponseWriter, r *http.Request) {
	if !s.allow(r, RL2FARegenerateCodes) {
		tooMany(w)
		return
	}
	claims, ok := ClaimsFromContext(r.Context())
	if !ok || claims.UserID == "" {
		unauthorized(w, "unauthorized")
		return
	}

	backupCodes, err := s.svc.RegenerateBackupCodes(r.Context(), claims.UserID)
	if err != nil {
		serverErr(w, "regenerate_codes_failed")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"backup_codes": backupCodes})
}
