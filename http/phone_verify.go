package authhttp

import (
	"net/http"
	"strings"

	core "github.com/open-rails/authkit/core"
)

func (s *Service) handlePhoneVerifyRequestPOST(w http.ResponseWriter, r *http.Request) {
	if s.rateLimited(w, r, RLPhoneVerifyRequest) {
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

	// Per-identifier check: prevents SMS bombing of a single phone number (and
	// the associated delivery cost) from many IPs.
	if s.rateLimitedByIdentifier(w, r, RLPhoneVerifyRequest, phone) {
		return
	}

	if !s.svc.SMSAvailable() {
		serverErr(w, "phone_verification_unavailable")
		return
	}
	if err := s.svc.RequestPhoneVerification(r.Context(), phone, 0); err != nil {
		if s.handleDeliveryError(w, r, "phone_verify_request", "send_phone_verification", err) {
			return
		}
		if handleVerificationRequestError(w, err) {
			return
		}
		s.logInternalError(r, "phone_verify_request", "request_phone_verification", "verification_request_failed", err)
		serverErr(w, "verification_request_failed")
		return
	}
	writeJSON(w, http.StatusAccepted, map[string]any{"ok": true})
}

func (s *Service) handlePhoneVerifyConfirmPOST(w http.ResponseWriter, r *http.Request) {
	if s.rateLimited(w, r, RLPhoneVerifyConfirm) {
		return
	}

	var req struct {
		PhoneNumber string `json:"phone_number"`
		Code        string `json:"code"`
	}
	if err := decodeJSON(r, &req); err != nil {
		badRequest(w, "invalid_request")
		return
	}

	phone := strings.TrimSpace(req.PhoneNumber)
	code := strings.ToUpper(strings.TrimSpace(req.Code))
	if phone == "" || code == "" {
		badRequest(w, "invalid_request")
		return
	}

	// Per-identifier check: prevents distributed brute-force of the 6-digit code
	// for a single phone number from many IPs.
	if s.rateLimitedByIdentifier(w, r, RLPhoneVerifyConfirm, phone) {
		return
	}

	userID, err := s.svc.ConfirmPendingPhoneRegistration(r.Context(), phone, code)
	if err == nil && userID != "" {
		if err := s.issueTokensForUser(w, r, userID, "phone_verification"); err != nil {
			serverErr(w, "token_issue_failed")
			return
		}
		return
	}

	userID, err = s.svc.ConfirmPhoneVerificationUserID(r.Context(), phone, code)
	if err != nil {
		badRequest(w, "invalid_or_expired_code")
		return
	}
	if err := s.issueTokensForUser(w, r, userID, "phone_verification"); err != nil {
		serverErr(w, "token_issue_failed")
		return
	}
}
