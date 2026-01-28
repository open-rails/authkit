package authhttp

import (
	"net/http"
	"strings"

	pwhash "github.com/PaulFidika/authkit/password"
)

func (s *Service) handlePhonePasswordResetRequestPOST(w http.ResponseWriter, r *http.Request) {
	if !s.svc.HasSMSSender() {
		serverErr(w, "sms_unavailable")
		return
	}
	if !s.allow(r, RLPasswordResetRequest) {
		tooMany(w)
		return
	}

	var req struct {
		PhoneNumber string `json:"phone_number"`
	}
	if err := decodeJSON(r, &req); err != nil {
		badRequest(w, "invalid_request")
		return
	}
	phone := strings.TrimSpace(req.PhoneNumber)
	if !reE164.MatchString(phone) {
		badRequest(w, "invalid_phone_number")
		return
	}
	_ = s.svc.RequestPhonePasswordReset(r.Context(), phone, 0)
	writeJSON(w, http.StatusAccepted, map[string]any{
		"ok":      true,
		"message": "If this phone number is registered, password reset instructions will be sent via SMS.",
	})
}

func (s *Service) handlePhonePasswordResetConfirmPOST(w http.ResponseWriter, r *http.Request) {
	if !s.allow(r, RLPasswordResetConfirm) {
		tooMany(w)
		return
	}

	var req struct {
		PhoneNumber string `json:"phone_number"` // legacy; no longer required
		Code        string `json:"code"`         // token from reset link (legacy field name)
		NewPassword string `json:"new_password"`
	}
	if err := decodeJSON(r, &req); err != nil {
		badRequest(w, "invalid_request")
		return
	}

	phone := strings.TrimSpace(req.PhoneNumber)
	code := strings.TrimSpace(req.Code)
	newPass := req.NewPassword

	if phone != "" && !reE164.MatchString(phone) {
		badRequest(w, "invalid_phone_number")
		return
	}
	if err := pwhash.Validate(newPass); err != nil {
		badRequest(w, "weak_password")
		return
	}

	userID, err := s.svc.ConfirmPasswordReset(r.Context(), code, newPass)
	if err != nil {
		badRequest(w, "invalid_or_expired_token")
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"ok":      true,
		"user_id": userID,
		"message": "Password reset successfully. You can now log in with your new password.",
	})
}
