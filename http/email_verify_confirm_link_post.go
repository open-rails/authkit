package authhttp

import (
	"context"
	"errors"
	"net/http"
	"strings"

	core "github.com/open-rails/authkit/core"
)

func (s *Service) handleEmailVerifyConfirmLinkPOST(w http.ResponseWriter, r *http.Request) {
	if s.rateLimited(w, r, RLEmailVerifyConfirm) {
		return
	}

	var req struct {
		Token      string `json:"token"`
		Identifier string `json:"identifier"`
		Email      string `json:"email"`
	}
	if err := decodeJSON(r, &req); err != nil || strings.TrimSpace(req.Token) == "" {
		badRequest(w, ErrInvalidRequest)
		return
	}

	token := strings.TrimSpace(req.Token)
	if userID, err := s.svc.ConfirmPendingRegistration(r.Context(), token); err == nil && strings.TrimSpace(userID) != "" {
		if err := s.issueTokensForUser(w, r, userID, "email_verification"); err != nil {
			if errors.Is(err, core.ErrUserBanned) {
				unauthorized(w, ErrUserBanned)
				return
			}
			serverErr(w, ErrTokenIssueFailed)
			return
		}
		return
	}
	if userID, err := s.svc.ConfirmEmailVerification(r.Context(), token); err == nil && strings.TrimSpace(userID) != "" {
		if err := s.issueTokensForUser(w, r, userID, "email_verification"); err != nil {
			if errors.Is(err, core.ErrUserBanned) {
				unauthorized(w, ErrUserBanned)
				return
			}
			serverErr(w, ErrTokenIssueFailed)
			return
		}
		return
	}

	s.handleEmailVerifyLinkFailure(w, r.Context(), req.Identifier, req.Email)
}

func (s *Service) handleEmailVerifyLinkFailure(w http.ResponseWriter, ctx context.Context, identifier, email string) {
	target := strings.TrimSpace(identifier)
	if target == "" {
		target = strings.TrimSpace(email)
	}
	if target == "" {
		badRequest(w, ErrInvalidOrExpiredToken)
		return
	}
	if err := core.ValidateEmail(target); err != nil {
		badRequest(w, ErrInvalidOrExpiredToken)
		return
	}
	target = core.NormalizeEmail(target)

	if u, err := s.svc.GetUserByEmail(ctx, target); err == nil && u != nil {
		if u.EmailVerified {
			sendErr(w, http.StatusConflict, ErrEmailAlreadyVerified)
			return
		}
		sendErr(w, http.StatusGone, ErrVerificationLinkExpired)
		return
	}
	if pending, err := s.svc.GetPendingRegistrationByEmail(ctx, target); err == nil && pending != nil {
		badRequest(w, ErrInvalidOrExpiredToken)
		return
	}
	sendErr(w, http.StatusGone, ErrVerificationLinkExpired)
}
