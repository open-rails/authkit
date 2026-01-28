package authhttp

import (
	"net/http"
	"regexp"
	"strings"

	pwhash "github.com/PaulFidika/authkit/password"
)

var reE164 = regexp.MustCompile(`^\+[1-9]\d{1,14}$`)

func (s *Service) handlePasswordResetRequestPOST(w http.ResponseWriter, r *http.Request) {
	if !s.allow(r, RLPasswordResetRequest) {
		tooMany(w)
		return
	}

	var req struct {
		Identifier string `json:"identifier"`
	}
	if err := decodeJSON(r, &req); err != nil {
		writeJSON(w, http.StatusAccepted, map[string]any{"ok": true})
		return
	}

	identifier := strings.TrimSpace(req.Identifier)
	if identifier == "" {
		writeJSON(w, http.StatusAccepted, map[string]any{"ok": true})
		return
	}

	isPhone := reE164.MatchString(identifier)
	if isPhone {
		if !s.svc.HasSMSSender() {
			serverErr(w, "sms_unavailable")
			return
		}
		_ = s.svc.RequestPhonePasswordReset(r.Context(), identifier, 0)
	} else {
		if !s.svc.HasEmailSender() {
			serverErr(w, "email_password_reset_unavailable")
			return
		}
		_ = s.svc.RequestPasswordReset(r.Context(), identifier, 0)
	}

	writeJSON(w, http.StatusAccepted, map[string]any{"ok": true, "message": "If this email or phone number is registered, password reset instructions will be sent."})
}

func (s *Service) handlePasswordResetConfirmPOST(w http.ResponseWriter, r *http.Request) {
	if !s.allow(r, RLPasswordResetConfirm) {
		tooMany(w)
		return
	}

	var req struct {
		Code        string `json:"code"`
		NewPassword string `json:"new_password"`
		Identifier  string `json:"identifier"`
	}
	if err := decodeJSON(r, &req); err != nil || req.Code == "" || req.NewPassword == "" || pwhash.Validate(req.NewPassword) != nil {
		badRequest(w, "invalid_request")
		return
	}

	code := strings.TrimSpace(req.Code)
	identifier := strings.TrimSpace(req.Identifier)

	var err error
	if identifier != "" && reE164.MatchString(identifier) {
		_, err = s.svc.ConfirmPhonePasswordReset(r.Context(), identifier, code, req.NewPassword)
	} else {
		_, err = s.svc.ConfirmPasswordReset(r.Context(), code, req.NewPassword)
	}
	if err != nil {
		badRequest(w, "invalid_or_expired_token")
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func (s *Service) handlePasswordResetConfirmLinkPOST(w http.ResponseWriter, r *http.Request) {
	if !s.allow(r, RLPasswordResetConfirm) {
		tooMany(w)
		return
	}

	var req struct {
		Token       string `json:"token"`
		NewPassword string `json:"new_password"`
	}
	if err := decodeJSON(r, &req); err != nil || strings.TrimSpace(req.Token) == "" || req.NewPassword == "" || pwhash.Validate(req.NewPassword) != nil {
		badRequest(w, "invalid_request")
		return
	}

	_, err := s.svc.ConfirmPasswordReset(r.Context(), strings.TrimSpace(req.Token), req.NewPassword)
	if err != nil {
		badRequest(w, "invalid_or_expired_token")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}
