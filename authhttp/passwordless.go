package authhttp

import (
	"errors"
	"net/http"
	"strings"

	"github.com/open-rails/authkit/embedded"
	"github.com/open-rails/authkit/iam"

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
		badRequest(w, iam.CodeInvalidRequest)
		return
	}
	identifier := strings.TrimSpace(req.Identifier)
	if identifier == "" {
		badRequest(w, iam.CodeInvalidRequest)
		return
	}
	if s.rateLimitedByIdentifier(w, r, RLPasswordlessStart, identifier) {
		return
	}

	_, err := s.svc.StartPasswordless(r.Context(), iam.PasswordlessStartRequest{
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
		badRequest(w, iam.CodeInvalidRequest)
		return
	}
	identifier := strings.TrimSpace(req.Identifier)
	if identifier != "" && s.rateLimitedByIdentifier(w, r, RLPasswordlessConfirm, identifier) {
		return
	}

	result, err := s.svc.PasswordlessLogin(r.Context(), embedded.PasswordlessLoginInput{Identifier: identifier, Code: strings.TrimSpace(req.Code), Token: strings.TrimSpace(req.Token), UserAgent: r.UserAgent(), IP: s.requestIP(r)})
	if err != nil {
		switch {
		case errors.Is(err, jwt.ErrTokenUnverifiable), errors.Is(err, jwt.ErrTokenInvalidClaims):
			logLoginFailed(s, r, "", "invalid_or_expired_passwordless_code")
			badRequest(w, iam.CodeInvalidOrExpiredCode)
		case errors.Is(err, iam.ErrRegistrationDisabled), errors.Is(err, iam.ErrPasswordlessDisabled):
			logLoginFailed(s, r, "", "passwordless_disabled")
			forbidden(w, iam.CodePasswordlessDisabled)
		default:
			logLoginFailed(s, r, "", "passwordless_failed")
			writeError(w, err)
		}
		return
	}

	if s.writeLoginContinuation(w, r, result, nil) {
		return
	}
	var extra map[string]any
	if result.ReturnTo != "" {
		extra = map[string]any{"return_to": result.ReturnTo}
	}
	s.writeTokenSetWith(w, r, http.StatusOK, result.Session.TokenSet(), extra)
}
