package authhttp

import (
	"errors"
	"net/http"
	"strings"

	authkit "github.com/open-rails/authkit"

	jwt "github.com/golang-jwt/jwt/v5"
)

func (s *Service) handlePasswordlessStartPOST(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Identifier         string `json:"identifier"`
		Mode               string `json:"mode"`
		ReturnTo           string `json:"return_to"`
		PreferredLanguage  string `json:"preferred_language"`
		AccountInviteToken string `json:"account_invite_token,omitempty"`
	}
	if err := decodeJSON(r, &req); err != nil {
		badRequest(w, authkit.CodeInvalidRequest)
		return
	}
	identifier := strings.TrimSpace(req.Identifier)
	if identifier == "" {
		badRequest(w, authkit.CodeInvalidRequest)
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
		writeError(w, err)
		return
	}
	accepted(w)
}

func (s *Service) handlePasswordlessConfirmPOST(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Identifier string `json:"identifier"`
		Code       string `json:"code"`
		Token      string `json:"token"`
	}
	if err := decodeJSON(r, &req); err != nil {
		badRequest(w, authkit.CodeInvalidRequest)
		return
	}
	identifier := strings.TrimSpace(req.Identifier)
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
		badRequest(w, authkit.CodeInvalidRequest)
		return
	}
	if err != nil {
		switch {
		case errors.Is(err, jwt.ErrTokenUnverifiable), errors.Is(err, jwt.ErrTokenInvalidClaims):
			if usedCode {
				s.svc.RecordFailedPasswordlessCode(r.Context(), identifier)
			}
			logLoginFailed(s, r, "", "invalid_or_expired_passwordless_code")
			badRequest(w, authkit.CodeInvalidOrExpiredCode)
		case errors.Is(err, authkit.ErrRegistrationDisabled), errors.Is(err, authkit.ErrPasswordlessDisabled):
			logLoginFailed(s, r, "", "passwordless_disabled")
			forbidden(w, authkit.CodePasswordlessDisabled)
		default:
			logLoginFailed(s, r, "", "passwordless_failed")
			writeError(w, err)
		}
		return
	}

	tokens, err := s.createTokensForUser(r, result.UserID, result.Method)
	if err != nil {
		writeError(w, err)
		return
	}
	var extra map[string]any
	if strings.TrimSpace(result.ReturnTo) != "" {
		extra = map[string]any{"return_to": result.ReturnTo}
	}
	s.writeTokenSetWith(w, r, http.StatusOK, tokens, extra)
}
