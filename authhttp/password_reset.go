package authhttp

import (
	"net/http"
	"strings"

	"github.com/open-rails/authkit/embedded"
)

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

	// Per-identifier check: prevents reset-mail bombing of a single address
	// from many IPs.
	if s.rateLimitedByIdentifier(w, r, RLPasswordResetRequest, email) {
		return
	}

	if !s.svc.HasEmailSender() {
		serverErr(w, ErrEmailPasswordResetUnavailable)
		return
	}
	ua := r.UserAgent()
	ip := remoteIP(r)
	if err := s.svc.RequestPasswordReset(r.Context(), email, 0, &ip, &ua); err != nil {
		if s.handleDeliveryError(w, r, "password_reset_request", "send_email_password_reset", err) {
			return
		}
		s.logInternalError(r, "password_reset_request", "request_password_reset", "password_reset_request_failed", err)
		serverErr(w, ErrPasswordResetRequestFailed)
		return
	}
	writeJSON(w, http.StatusAccepted, map[string]any{"ok": true, "message": "If this email is registered, password reset instructions will be sent."})
}

func (s *Service) handleEmailPasswordResetConfirmPOST(w http.ResponseWriter, r *http.Request) {
	if s.rateLimited(w, r, RLPasswordResetConfirm) {
		return
	}

	var req struct {
		Token       string `json:"token"`
		NewPassword string `json:"new_password"`
	}
	if err := decodeJSON(r, &req); err != nil || strings.TrimSpace(req.Token) == "" || req.NewPassword == "" {
		badRequest(w, ErrInvalidRequest)
		return
	}
	if err := embedded.ValidatePassword(req.NewPassword); err != nil {
		badRequest(w, ErrorCode(embedded.ValidationErrorCode(err)))
		return
	}

	if _, ok := s.confirmPasswordReset(w, r, strings.TrimSpace(req.Token), req.NewPassword); !ok {
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

// confirmPasswordReset runs the shared password-reset confirm + error mapping for
// both the email and phone channels (#179). On failure it writes the response and
// returns ok=false; on success it returns the user ID for the channel-specific
// success payload. The request halves (anti-enumeration vs explicit) stay separate.
func (s *Service) confirmPasswordReset(w http.ResponseWriter, r *http.Request, token, newPassword string) (string, bool) {
	userID, err := s.svc.ConfirmPasswordReset(r.Context(), token, newPassword)
	if err != nil {
		if code := ErrorCode(embedded.ValidationErrorCode(err)); code != "" {
			badRequest(w, code)
			return "", false
		}
		badRequest(w, ErrInvalidOrExpiredToken)
		return "", false
	}
	return userID, true
}
