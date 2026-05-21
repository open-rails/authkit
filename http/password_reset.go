package authhttp

import (
	"net/http"
	"regexp"
	"strings"
	"time"

	core "github.com/open-rails/authkit/core"
)

var reE164 = regexp.MustCompile(`^\+[1-9]\d{1,14}$`)

func (s *Service) handleEmailPasswordResetRequestPOST(w http.ResponseWriter, r *http.Request) {
	if s.rateLimited(w, r, RLPasswordResetRequest) {
		return
	}

	var req struct {
		Email string `json:"email"`
	}
	if err := decodeJSON(r, &req); err != nil {
		writeJSON(w, http.StatusAccepted, map[string]any{"ok": true})
		return
	}

	email := strings.TrimSpace(req.Email)
	if email == "" {
		writeJSON(w, http.StatusAccepted, map[string]any{"ok": true})
		return
	}
	if !s.svc.HasEmailSender() {
		serverErr(w, "email_password_reset_unavailable")
		return
	}
	if err := s.svc.RequestPasswordReset(r.Context(), email, 0); err != nil {
		if s.handleDeliveryError(w, r, "password_reset_request", "send_email_password_reset", err) {
			return
		}
		s.logInternalError(r, "password_reset_request", "request_password_reset", "password_reset_request_failed", err)
		serverErr(w, "password_reset_request_failed")
		return
	}
	writeJSON(w, http.StatusAccepted, map[string]any{"ok": true, "message": "If this email is registered, password reset instructions will be sent."})
}

func (s *Service) handleEmailPasswordResetConfirmPOST(w http.ResponseWriter, r *http.Request) {
	if s.rateLimited(w, r, RLPasswordResetConfirm) {
		return
	}

	var req struct {
		ResetSession string `json:"reset_session"`
		NewPassword  string `json:"new_password"`
	}
	if err := decodeJSON(r, &req); err != nil || strings.TrimSpace(req.ResetSession) == "" || req.NewPassword == "" {
		badRequest(w, "invalid_request")
		return
	}
	if err := core.ValidatePassword(req.NewPassword); err != nil {
		badRequest(w, core.ValidationErrorCode(err))
		return
	}

	_, err := s.svc.ConfirmPasswordResetWithSession(r.Context(), strings.TrimSpace(req.ResetSession), req.NewPassword)
	if err != nil {
		if code := core.ValidationErrorCode(err); code != "" {
			badRequest(w, code)
			return
		}
		badRequest(w, "invalid_or_expired_reset_session")
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func (s *Service) handleEmailPasswordResetConfirmLinkPOST(w http.ResponseWriter, r *http.Request) {
	if s.rateLimited(w, r, RLPasswordResetConfirm) {
		return
	}

	var req struct {
		Token string `json:"token"`
	}
	if err := decodeJSON(r, &req); err != nil || strings.TrimSpace(req.Token) == "" {
		badRequest(w, "invalid_request")
		return
	}

	resetSession, err := s.svc.BeginPasswordReset(r.Context(), strings.TrimSpace(req.Token), 15*time.Minute)
	if err != nil {
		badRequest(w, "invalid_or_expired_token")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "reset_session": resetSession})
}
