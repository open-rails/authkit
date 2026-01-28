package authhttp

import (
	"net/http"
	"strings"
)

func (s *Service) handlePhoneVerifyRequestPOST(w http.ResponseWriter, r *http.Request) {
	if !s.svc.HasSMSSender() {
		serverErr(w, "phone_verification_unavailable")
		return
	}
	if !s.allow(r, RLPhoneVerifyRequest) {
		tooMany(w)
		return
	}

	var req struct {
		PhoneNumber string `json:"phone_number"`
	}
	if err := decodeJSON(r, &req); err != nil {
		writeJSON(w, http.StatusAccepted, map[string]any{"ok": true})
		return
	}

	phone := strings.TrimSpace(req.PhoneNumber)
	if phone == "" || !reE164.MatchString(phone) {
		writeJSON(w, http.StatusAccepted, map[string]any{"ok": true})
		return
	}

	_ = s.svc.RequestPhoneVerification(r.Context(), phone, 0)
	writeJSON(w, http.StatusAccepted, map[string]any{"ok": true})
}

func (s *Service) handlePhoneVerifyConfirmPOST(w http.ResponseWriter, r *http.Request) {
	if !s.allow(r, RLEmailVerifyConfirm) {
		tooMany(w)
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

	userID, err := s.svc.ConfirmPendingPhoneRegistration(r.Context(), phone, code)
	if err != nil {
		badRequest(w, "invalid_or_expired_code")
		return
	}

	if err := s.issueTokensForUser(w, r, userID, "phone_verification"); err != nil {
		serverErr(w, "token_issue_failed")
		return
	}
}
