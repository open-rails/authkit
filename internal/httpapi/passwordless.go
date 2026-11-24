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
	var req PasswordlessStartRequest
	if err := decodeJSON(r, &req); err != nil {
		s.fail(w, errmodel.CodeInvalidRequest)
		return
	}
	identifier := strings.TrimSpace(req.Identifier)
	if identifier == "" {
		s.fail(w, errmodel.CodeInvalidRequest)
		return
	}
	if !s.humanProven(w, r, req.CaptchaToken) {
		return
	}
	// The address's send quota is the engine's, and never refuses.
	out, err := s.svc.StartPasswordless(r.Context(), authflow.PasswordlessStartRequest{
		Identifier:         identifier,
		Mode:               req.Mode,
		ReturnTo:           req.ReturnTo,
		PreferredLanguage:  req.PreferredLanguage,
		AccountInviteToken: req.InviteCode,
	})
	if err != nil {
		s.writeError(w, err)
		return
	}
	writeJSON(w, http.StatusAccepted, CodeChallenge{Challenge: out.Challenge})
}

// POST /passwordless/confirm — {challenge, code} or {token}. A code is checked
// only against the challenge it names; there is no budget per email or phone.
func (s *Service) handlePasswordlessConfirmPOST(w http.ResponseWriter, r *http.Request) {
	var req CodeOrLinkRequest
	if err := decodeJSON(r, &req); err != nil {
		s.fail(w, errmodel.CodeInvalidRequest)
		return
	}
	in := authflow.PasswordlessLoginInput{Identifier: strings.TrimSpace(req.Identifier), Challenge: strings.TrimSpace(req.Challenge), Code: strings.TrimSpace(req.Code),
		Token: strings.TrimSpace(req.Token), Agreements: req.Agreements, UserAgent: r.UserAgent(), IP: s.requestIP(r)}
	if in.Code != "" && in.Token == "" && in.Challenge == "" {
		s.fail(w, errmodel.CodeInvalidRequest, errmodel.WithParam("challenge"))
		return
	}
	result, err := s.svc.PasswordlessLogin(r.Context(), in)
	if err != nil {
		switch {
		case errors.Is(err, jwt.ErrTokenUnverifiable), errors.Is(err, jwt.ErrTokenInvalidClaims):
			logLoginFailed(s, r, "", "invalid_or_expired_passwordless_code")
			if strings.TrimSpace(req.Code) == "" && strings.TrimSpace(req.Token) != "" {
				s.fail(w, errmodel.CodeInvalidLink)
			} else {
				s.fail(w, errmodel.CodeInvalidCode)
			}
		case errors.Is(err, errmodel.ErrRegistrationDisabled), errors.Is(err, errmodel.ErrPasswordlessDisabled):
			logLoginFailed(s, r, "", "passwordless_disabled")
			s.fail(w, errmodel.CodePasswordlessDisabled)
		default:
			logLoginFailed(s, r, "", "passwordless_failed")
			s.writeError(w, err)
		}
		return
	}

	s.writeAuthResult(w, r, result, authExtras{})
}
