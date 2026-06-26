package authhttp

import (
	"net/http"
	"strings"

	"github.com/open-rails/authkit/embedded"
)

func (s *Service) handlePhonePasswordResetRequestPOST(w http.ResponseWriter, r *http.Request) {
	if !s.svc.SMSAvailable() {
		serverErr(w, ErrSMSUnavailable)
		return
	}
	if s.rateLimited(w, r, RLPasswordResetRequest) {
		return
	}

	var req struct {
		PhoneNumber string `json:"phone_number"`
	}
	if err := decodeJSON(r, &req); err != nil {
		badRequest(w, ErrInvalidRequest)
		return
	}
	phone := strings.TrimSpace(req.PhoneNumber)
	if err := embedded.ValidatePhone(phone); err != nil {
		badRequest(w, ErrorCode(embedded.ValidationErrorCode(err)))
		return
	}
	phone = embedded.NormalizePhone(phone)

	// Per-identifier check: prevents reset-SMS bombing of a single phone number
	// (and the associated delivery cost) from many IPs.
	if s.rateLimitedByIdentifier(w, r, RLPasswordResetRequest, phone) {
		return
	}
	ua := r.UserAgent()
	ip := clientIP(r)
	if err := s.svc.RequestPhonePasswordReset(r.Context(), phone, 0, &ip, &ua); err != nil {
		if s.handleDeliveryError(w, r, "phone_password_reset_request", "send_sms_password_reset", err) {
			return
		}
		s.logInternalError(r, "phone_password_reset_request", "request_phone_password_reset", "password_reset_request_failed", err)
		serverErr(w, ErrPasswordResetRequestFailed)
		return
	}
	writeJSON(w, http.StatusAccepted, map[string]any{
		"ok":      true,
		"message": "If this phone number is registered, password reset instructions will be sent via SMS.",
	})
}

func (s *Service) handlePhonePasswordResetConfirmPOST(w http.ResponseWriter, r *http.Request) {
	if s.rateLimited(w, r, RLPasswordResetConfirm) {
		return
	}

	var req struct {
		Token       string `json:"token"`
		NewPassword string `json:"new_password"`
	}
	if err := decodeJSON(r, &req); err != nil {
		badRequest(w, ErrInvalidRequest)
		return
	}

	token := strings.TrimSpace(req.Token)
	newPass := req.NewPassword

	if token == "" {
		badRequest(w, ErrInvalidRequest)
		return
	}
	if err := embedded.ValidatePassword(newPass); err != nil {
		badRequest(w, ErrorCode(embedded.ValidationErrorCode(err)))
		return
	}

	userID, err := s.svc.ConfirmPasswordReset(r.Context(), token, newPass)
	if err != nil {
		if code := ErrorCode(embedded.ValidationErrorCode(err)); code != "" {
			badRequest(w, code)
			return
		}
		badRequest(w, ErrInvalidOrExpiredToken)
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"ok":      true,
		"user_id": userID,
		"message": "Password reset successfully. You can now log in with your new password.",
	})
}
