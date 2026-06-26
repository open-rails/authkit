package authhttp

import (
	"context"
	"errors"
	authkit "github.com/open-rails/authkit"
	"net/http"
	"strings"

	"github.com/open-rails/authkit/embedded"
)

func (s *Service) confirmEmailVerificationToken(w http.ResponseWriter, r *http.Request, token, identifier, email string) {
	if userID, err := s.svc.ConfirmPendingRegistrationByToken(r.Context(), token); err == nil && strings.TrimSpace(userID) != "" {
		if err := s.issueTokensForUser(w, r, userID, "email_verification"); err != nil {
			if errors.Is(err, authkit.ErrUserBanned) {
				unauthorized(w, ErrUserBanned)
				return
			}
			serverErr(w, ErrTokenIssueFailed)
			return
		}
		return
	}
	if userID, err := s.svc.ConfirmEmailVerificationByToken(r.Context(), token); err == nil && strings.TrimSpace(userID) != "" {
		if err := s.issueTokensForUser(w, r, userID, "email_verification"); err != nil {
			if errors.Is(err, authkit.ErrUserBanned) {
				unauthorized(w, ErrUserBanned)
				return
			}
			serverErr(w, ErrTokenIssueFailed)
			return
		}
		return
	}
	if userID, err := s.svc.ConfirmEmailChangeByToken(r.Context(), token); err == nil && strings.TrimSpace(userID) != "" {
		writeJSON(w, http.StatusOK, map[string]any{"ok": true, "message": "Email changed successfully"})
		return
	}

	s.handleEmailVerifyLinkFailure(w, r.Context(), identifier, email)
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
	if err := embedded.ValidateEmail(target); err != nil {
		badRequest(w, ErrInvalidOrExpiredToken)
		return
	}
	target = embedded.NormalizeEmail(target)

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
