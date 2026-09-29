package httpapi

import (
	"errors"
	"net/http"
	"strings"

	"github.com/open-rails/authkit/internal/authflow"
	"github.com/open-rails/authkit/internal/errmodel"

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
		fail(w, errmodel.CodeInvalidRequest)
		return
	}
	identifier := strings.TrimSpace(req.Identifier)
	if identifier == "" {
		fail(w, errmodel.CodeInvalidRequest)
		return
	}
	if s.rateLimitedByIdentifier(w, r, RLPasswordlessStart, identifier) {
		return
	}

	_, err := s.svc.StartPasswordless(r.Context(), authflow.PasswordlessStartRequest{
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
		fail(w, errmodel.CodeInvalidRequest)
		return
	}
	identifier := strings.TrimSpace(req.Identifier)
	if identifier != "" && s.rateLimitedByIdentifier(w, r, RLPasswordlessConfirm, identifier) {
		return
	}

	result, err := s.svc.PasswordlessLogin(r.Context(), authflow.PasswordlessLoginInput{Identifier: identifier, Code: strings.TrimSpace(req.Code), Token: strings.TrimSpace(req.Token), UserAgent: r.UserAgent(), IP: s.requestIP(r)})
	if err != nil {
		switch {
		case errors.Is(err, jwt.ErrTokenUnverifiable), errors.Is(err, jwt.ErrTokenInvalidClaims):
			logLoginFailed(s, r, "", "invalid_or_expired_passwordless_code")
			if strings.TrimSpace(req.Code) == "" && strings.TrimSpace(req.Token) != "" {
				fail(w, errmodel.CodeInvalidLink)
			} else {
				fail(w, errmodel.CodeInvalidCode)
			}
		case errors.Is(err, errmodel.ErrRegistrationDisabled), errors.Is(err, errmodel.ErrPasswordlessDisabled):
			logLoginFailed(s, r, "", "passwordless_disabled")
			fail(w, errmodel.CodePasswordlessDisabled)
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
