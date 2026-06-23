package authhttp

import (
	"crypto/rand"
	"fmt"
	"math/big"
	"net/http"
	"strings"

	core "github.com/open-rails/authkit/core"
)

type twoFactorStatusResponse struct {
	Enabled              bool                      `json:"enabled"`
	Method               string                    `json:"method"`
	PhoneNumber          *string                   `json:"phone_number,omitempty"`
	DefaultFactor        *twoFactorFactorResponse  `json:"default_factor,omitempty"`
	Factors              []twoFactorFactorResponse `json:"factors,omitempty"`
	AvailableFactors     []twoFactorFactorResponse `json:"available_factors,omitempty"`
	AllowedMethods       []string                  `json:"allowed_methods,omitempty"`
	BackupCodesRemaining int                       `json:"backup_codes_remaining,omitempty"`
}

type twoFactorFactorResponse struct {
	ID          string  `json:"id,omitempty"`
	Method      string  `json:"method"`
	IsDefault   bool    `json:"is_default,omitempty"`
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
		writeJSON(w, http.StatusOK, twoFactorStatusResponse{Enabled: false, Method: "email", AllowedMethods: []string{"email", "sms", "totp"}})
		return
	}

	factors := twoFactorFactorResponses(settings.Factors)
	writeJSON(w, http.StatusOK, twoFactorStatusResponse{
		Enabled:              settings.Enabled,
		Method:               settings.Method,
		PhoneNumber:          settings.PhoneNumber,
		DefaultFactor:        defaultTwoFactorFactorResponse(factors),
		Factors:              factors,
		AvailableFactors:     factors,
		AllowedMethods:       []string{"email", "sms", "totp"},
		BackupCodesRemaining: len(settings.BackupCodes),
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
		Default     bool    `json:"default,omitempty"`
		FactorID    string  `json:"factor_id,omitempty"`
	}
	if err := decodeJSON(r, &req); err != nil {
		badRequest(w, ErrInvalidRequest)
		return
	}

	method := strings.ToLower(strings.TrimSpace(req.Method))
	if method == "" && req.Default && strings.TrimSpace(req.FactorID) != "" {
		if err := s.svc.SetDefault2FAFactor(r.Context(), claims.UserID, strings.TrimSpace(req.FactorID)); err != nil {
			serverErr(w, ErrEnableTwoFAFailed)
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"ok": true})
		return
	}
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

		backupCodes, err := s.svc.EnableTOTP2FADefault(r.Context(), claims.UserID, req.Code, req.Default)
		if err != nil {
			badRequest(w, ErrInvalidCode)
			return
		}
		resp := map[string]any{
			"enabled":      true,
			"method":       method,
			"backup_codes": backupCodes,
		}
		if len(backupCodes) == 0 {
			delete(resp, "backup_codes")
		}
		writeJSON(w, http.StatusOK, resp)
		return
	}

	var backupCodes []string
	var err error
	if req.Default {
		backupCodes, err = s.svc.Enable2FADefault(r.Context(), claims.UserID, method, req.PhoneNumber)
	} else {
		backupCodes, err = s.svc.Enable2FA(r.Context(), claims.UserID, method, req.PhoneNumber)
	}
	if err != nil {
		serverErr(w, ErrEnableTwoFAFailed)
		return
	}

	resp := map[string]any{
		"enabled":      true,
		"method":       method,
		"backup_codes": backupCodes,
	}
	if len(backupCodes) == 0 {
		delete(resp, "backup_codes")
	}
	writeJSON(w, http.StatusOK, resp)
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
	if ok, _ := s.requireFreshAuthOrPassword(w, r, claims, ""); !ok {
		return
	}

	factorID := strings.TrimSpace(r.URL.Query().Get("factor_id"))
	var body struct {
		FactorID string `json:"factor_id"`
	}
	_ = decodeJSON(r, &body)
	if factorID == "" {
		factorID = strings.TrimSpace(body.FactorID)
	}
	var err error
	if factorID == "" {
		err = s.svc.Disable2FA(r.Context(), claims.UserID)
	} else {
		err = s.svc.Disable2FAFactor(r.Context(), claims.UserID, factorID)
	}
	if err != nil {
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
	if ok, _ := s.requireFreshAuthOrPassword(w, r, claims, ""); !ok {
		return
	}

	backupCodes, err := s.svc.RegenerateBackupCodes(r.Context(), claims.UserID)
	if err != nil {
		serverErr(w, ErrRegenerateCodesFailed)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"backup_codes": backupCodes})
}

func twoFactorFactorResponses(factors []core.TwoFactorFactor) []twoFactorFactorResponse {
	out := make([]twoFactorFactorResponse, 0, len(factors))
	for _, factor := range factors {
		out = append(out, twoFactorFactorResponse{
			ID:          factor.ID,
			Method:      factor.Method,
			IsDefault:   factor.IsDefault,
			PhoneNumber: factor.PhoneNumber,
		})
	}
	return out
}

func defaultTwoFactorFactorResponse(factors []twoFactorFactorResponse) *twoFactorFactorResponse {
	for _, factor := range factors {
		if factor.IsDefault {
			f := factor
			return &f
		}
	}
	if len(factors) == 0 {
		return nil
	}
	return &factors[0]
}
