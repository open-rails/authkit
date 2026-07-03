package authhttp

import (
	"errors"
	authkit "github.com/open-rails/authkit"
	"net/http"
	"strings"

	jwt "github.com/golang-jwt/jwt/v5"
	"github.com/open-rails/authkit/embedded"
)

func (s *Service) handlePasswordlessStartPOST(w http.ResponseWriter, r *http.Request) {
	if s.rateLimited(w, r, RLPasswordlessStart) {
		return
	}
	var req struct {
		Identifier         string `json:"identifier"`
		Email              string `json:"email"`
		PhoneNumber        string `json:"phone_number"`
		Mode               string `json:"mode"`
		ReturnTo           string `json:"return_to"`
		PreferredLanguage  string `json:"preferred_language"`
		AccountInviteToken string `json:"account_invite_token,omitempty"`
	}
	if err := decodeJSON(r, &req); err != nil {
		badRequest(w, ErrInvalidRequest)
		return
	}
	identifier := passwordlessIdentifier(req.Identifier, req.Email, req.PhoneNumber)
	if identifier == "" {
		badRequest(w, ErrInvalidRequest)
		return
	}
	if s.rateLimitedByIdentifier(w, r, RLPasswordlessStart, identifier) {
		return
	}

	_, err := s.svc.StartPasswordless(r.Context(), authkit.PasswordlessStartRequest{
		Identifier:         identifier,
		Mode:               req.Mode,
		ReturnTo:           req.ReturnTo,
		PreferredLanguage:  req.PreferredLanguage,
		AccountInviteToken: req.AccountInviteToken,
	})
	if err != nil {
		if errors.Is(err, authkit.ErrPasswordlessDisabled) {
			forbidden(w, ErrPasswordlessDisabled)
			return
		}
		if errors.Is(err, authkit.ErrRegistrationDisabled) {
			registrationDisabled(w)
			return
		}
		if code := ErrorCode(embedded.ValidationErrorCode(err)); code != "" {
			badRequest(w, code)
			return
		}
		if errors.Is(err, authkit.ErrEmailSenderUnavailable) {
			serverErr(w, ErrEmailVerificationUnavailable)
			return
		}
		if errors.Is(err, authkit.ErrSMSSenderUnavailable) {
			serverErr(w, ErrPhoneVerificationUnavailable)
			return
		}
		s.logInternalError(r, "passwordless_start", "start_passwordless", "passwordless_start_failed", err)
		serverErr(w, ErrDatabaseError)
		return
	}
	writeJSON(w, http.StatusAccepted, map[string]any{"ok": true})
}

func (s *Service) handlePasswordlessConfirmPOST(w http.ResponseWriter, r *http.Request) {
	if s.rateLimited(w, r, RLPasswordlessConfirm) {
		return
	}
	var req struct {
		Identifier  string `json:"identifier"`
		Email       string `json:"email"`
		PhoneNumber string `json:"phone_number"`
		Code        string `json:"code"`
		Token       string `json:"token"`
	}
	if err := decodeJSON(r, &req); err != nil {
		badRequest(w, ErrInvalidRequest)
		return
	}
	identifier := passwordlessIdentifier(req.Identifier, req.Email, req.PhoneNumber)
	if identifier != "" && s.rateLimitedByIdentifier(w, r, RLPasswordlessConfirm, identifier) {
		return
	}

	var result authkit.PasswordlessConfirmResult
	var err error
	usedCode := false
	if token := strings.TrimSpace(req.Token); token != "" {
		result, err = s.svc.ConfirmPasswordlessToken(r.Context(), token)
	} else if identifier != "" && strings.TrimSpace(req.Code) != "" {
		usedCode = true
		result, err = s.svc.ConfirmPasswordlessCode(r.Context(), identifier, strings.TrimSpace(req.Code))
	} else {
		badRequest(w, ErrInvalidRequest)
		return
	}
	if err != nil {
		switch {
		case errors.Is(err, jwt.ErrTokenUnverifiable), errors.Is(err, jwt.ErrTokenInvalidClaims):
			if usedCode {
				s.svc.RecordFailedPasswordlessCode(r.Context(), identifier)
			}
			logLoginFailed(s, r, "", "invalid_or_expired_passwordless_code")
			badRequest(w, ErrInvalidOrExpiredCode)
		case errors.Is(err, authkit.ErrRegistrationDisabled), errors.Is(err, authkit.ErrPasswordlessDisabled):
			logLoginFailed(s, r, "", "passwordless_disabled")
			forbidden(w, ErrPasswordlessDisabled)
		default:
			logLoginFailed(s, r, "", "passwordless_failed")
			s.logInternalError(r, "passwordless_confirm", "confirm_passwordless", "passwordless_confirm_failed", err)
			serverErr(w, ErrDatabaseError)
		}
		return
	}

	tokens, err := s.createTokensForUser(r, result.UserID, result.Method)
	if err != nil {
		s.logInternalError(r, "passwordless_confirm", "issue_tokens", "passwordless_issue_tokens_failed", err)
		serverErr(w, ErrAccessTokenCreateFailed)
		return
	}
	var extra map[string]any
	if strings.TrimSpace(result.ReturnTo) != "" {
		extra = map[string]any{"return_to": result.ReturnTo}
	}
	writeAccessTokenJSON(w, http.StatusOK, tokens, extra)
}

func passwordlessIdentifier(identifier, email, phone string) string {
	return firstTrimmedNonEmpty(identifier, email, phone)
}
