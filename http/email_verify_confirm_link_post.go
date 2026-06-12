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
		badRequest(w, "invalid_request")
		return
	}

	token := strings.TrimSpace(req.Token)
	if userID, err := s.svc.ConfirmPendingRegistration(r.Context(), token); err == nil && strings.TrimSpace(userID) != "" {
		if err := s.issueTokensForUser(w, r, userID, "email_verification"); err != nil {
			if errors.Is(err, core.ErrUserBanned) {
				unauthorized(w, "user_banned")
				return
			}
			serverErr(w, "token_issue_failed")
			return
		}
		return
	}
	if userID, err := s.svc.ConfirmEmailVerification(r.Context(), token); err == nil && strings.TrimSpace(userID) != "" {
		if err := s.issueTokensForUser(w, r, userID, "email_verification"); err != nil {
			if errors.Is(err, core.ErrUserBanned) {
				unauthorized(w, "user_banned")
				return
			}
			serverErr(w, "token_issue_failed")
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
		badRequest(w, "invalid_or_expired_token")
		return
	}
	if err := core.ValidateEmail(target); err != nil {
		badRequest(w, "invalid_or_expired_token")
		return
	}
	target = core.NormalizeEmail(target)

	if u, err := s.svc.GetUserByEmail(ctx, target); err == nil && u != nil {
		if u.EmailVerified {
			sendErr(w, http.StatusConflict, "email_already_verified")
			return
		}
		sendErr(w, http.StatusGone, "verification_link_expired")
		return
	}
	if pending, err := s.svc.GetPendingRegistrationByEmail(ctx, target); err == nil && pending != nil {
		badRequest(w, "invalid_or_expired_token")
		return
	}
	sendErr(w, http.StatusGone, "verification_link_expired")
}
