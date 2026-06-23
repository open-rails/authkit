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
		badRequest(w, ErrInvalidRequest)
		return
	}

	phone := strings.TrimSpace(req.PhoneNumber)
	if err := core.ValidatePhone(phone); err != nil {
		badRequest(w, ErrorCode(core.ValidationErrorCode(err)))
		return
	}
	phone = core.NormalizePhone(phone)

	// Per-identifier check: prevents SMS bombing of a single phone number (and
	// the associated delivery cost) from many IPs.
	if s.rateLimitedByIdentifier(w, r, RLPhoneVerifyRequest, phone) {
		return
	}

	if !s.svc.SMSAvailable() {
		serverErr(w, ErrPhoneVerificationUnavailable)
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
		serverErr(w, ErrVerificationRequestFailed)
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
		Token       string `json:"token"`
		Identifier  string `json:"identifier"`
	}
	if err := decodeJSON(r, &req); err != nil {
		badRequest(w, ErrInvalidRequest)
		return
	}
	if token := strings.TrimSpace(req.Token); token != "" {
		s.confirmPhoneVerificationToken(w, r, token, req.Identifier, req.PhoneNumber)
		return
	}

	phone := strings.TrimSpace(req.PhoneNumber)
	code := strings.ToUpper(strings.TrimSpace(req.Code))
	if phone == "" || code == "" {
		badRequest(w, ErrInvalidRequest)
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
			serverErr(w, ErrTokenIssueFailed)
			return
		}
		return
	}

	userID, err = s.svc.ConfirmPhoneVerificationUserID(r.Context(), phone, code)
	if err != nil {
		badRequest(w, ErrInvalidOrExpiredCode)
		return
	}
	if err := s.issueTokensForUser(w, r, userID, "phone_verification"); err != nil {
		serverErr(w, ErrTokenIssueFailed)
		return
	}
}
