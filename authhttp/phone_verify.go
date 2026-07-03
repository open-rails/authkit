package authhttp

import (
	"net/http"
	"strings"

	"github.com/open-rails/authkit/embedded"
)

func (s *Service) handlePhoneVerifyRequestPOST(w http.ResponseWriter, r *http.Request) {
	if s.rateLimited(w, r, RLPhoneVerifyRequest) {
		return
	}

	var req struct {
		PhoneNumber string `json:"phone_number"`
		Password    string `json:"password"`
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

	// Per-identifier check: prevents SMS bombing of a single phone number (and
	// the associated delivery cost) from many IPs.
	if s.rateLimitedByIdentifier(w, r, RLPhoneVerifyRequest, phone) {
		return
	}

	if !s.svc.SMSAvailable() {
		serverErr(w, ErrPhoneVerificationUnavailable)
		return
	}
	if claims, ok := ClaimsFromContext(r.Context()); ok && claims.UserID != "" {
		ok, authMeta := s.requireFreshAuthOrPassword(w, r, claims, req.Password)
		if s.rateLimited(w, r, RLUserPhoneChangeRequest) || !ok {
			return
		}
		if err := s.svc.RequestPhoneChange(r.Context(), claims.UserID, phone); err != nil {
			if s.handleDeliveryError(w, r, "user_phone_change_request", "send_phone_verification", err) {
				return
			}
			if code := ErrorCode(embedded.ValidationErrorCode(err)); code != "" {
				badRequest(w, code)
				return
			}
			mapContactChangeError(w, err, ErrPhoneUnchanged, ErrPhoneInUse, ErrFailedToRequestPhoneChange)
			return
		}
		resp := map[string]any{"ok": true, "message": "Verification sent to new phone"}
		for k, v := range authMeta {
			resp[k] = v
		}
		writeJSON(w, http.StatusAccepted, resp)
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
		s.svc.ClearPhoneVerifyCodeAttempts(r.Context(), phone)
		if err := s.issueTokensForUser(w, r, userID, "phone_verification"); err != nil {
			serverErr(w, ErrTokenIssueFailed)
			return
		}
		return
	}

	userID, err = s.svc.ConfirmPhoneVerificationUserID(r.Context(), phone, code)
	if err == nil && userID != "" {
		s.svc.ClearPhoneVerifyCodeAttempts(r.Context(), phone)
		if err := s.issueTokensForUser(w, r, userID, "phone_verification"); err != nil {
			serverErr(w, ErrTokenIssueFailed)
			return
		}
		return
	}

	if claims, ok := ClaimsFromContext(r.Context()); ok && claims.UserID != "" {
		if err := s.svc.ConfirmPhoneChange(r.Context(), claims.UserID, phone, code); err == nil {
			s.svc.ClearPhoneVerifyCodeAttempts(r.Context(), phone)
			writeJSON(w, http.StatusOK, map[string]any{"ok": true, "message": "Phone number changed successfully"})
			return
		}
	}

	// All confirm paths failed: count the bad guess and (after the cap) invalidate
	// the outstanding code for this number — mirrors email_verify.go.
	s.svc.RecordFailedPhoneVerifyCode(r.Context(), phone)
	badRequest(w, ErrInvalidOrExpiredCode)
}
