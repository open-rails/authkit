package authhttp

import (
	"net/http"
	"strings"

	core "github.com/open-rails/authkit/core"
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
	if err := core.ValidatePhone(phone); err != nil {
		badRequest(w, core.ValidationErrorCode(err))
		return
	}
	phone = core.NormalizePhone(phone)
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
		ResetSession string `json:"reset_session"`
		NewPassword  string `json:"new_password"`
	}
	if err := decodeJSON(r, &req); err != nil {
		badRequest(w, "invalid_request")
		return
	}

	resetSession := strings.TrimSpace(req.ResetSession)
	newPass := req.NewPassword

	if resetSession == "" {
		badRequest(w, "invalid_request")
		return
	}
	if err := core.ValidatePassword(newPass); err != nil {
		badRequest(w, core.ValidationErrorCode(err))
		return
	}

	userID, err := s.svc.ConfirmPasswordResetWithSession(r.Context(), resetSession, newPass)
	if err != nil {
		if code := core.ValidationErrorCode(err); code != "" {
			badRequest(w, code)
			return
		}
		badRequest(w, "invalid_or_expired_reset_session")
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"ok":      true,
		"user_id": userID,
		"message": "Password reset successfully. You can now log in with your new password.",
	})
}
