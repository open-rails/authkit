package authhttp

import (
	"context"
	"net/http"
	"strings"

	core "github.com/open-rails/authkit/core"
)

func (s *Service) confirmPhoneVerificationToken(w http.ResponseWriter, r *http.Request, token, identifier, phoneNumber string) {
	if userID, err := s.svc.ConfirmPendingPhoneRegistrationByToken(r.Context(), token); err == nil && strings.TrimSpace(userID) != "" {
		if err := s.issueTokensForUser(w, r, userID, "phone_verification"); err != nil {
			serverErr(w, ErrTokenIssueFailed)
			return
		}
		return
	}
	if userID, err := s.svc.ConfirmPhoneVerificationByTokenUserID(r.Context(), token); err == nil && strings.TrimSpace(userID) != "" {
		if err := s.issueTokensForUser(w, r, userID, "phone_verification"); err != nil {
			serverErr(w, ErrTokenIssueFailed)
			return
		}
		return
	}
	if userID, err := s.svc.ConfirmPhoneChangeByToken(r.Context(), token); err == nil && strings.TrimSpace(userID) != "" {
		writeJSON(w, http.StatusOK, map[string]any{"ok": true, "message": "Phone number changed successfully"})
		return
	}

	s.handlePhoneVerifyLinkFailure(w, r.Context(), identifier, phoneNumber)
}

func (s *Service) handlePhoneVerifyLinkFailure(w http.ResponseWriter, ctx context.Context, identifier, phoneNumber string) {
	target := strings.TrimSpace(identifier)
	if target == "" {
		target = strings.TrimSpace(phoneNumber)
	}
	if target == "" {
		badRequest(w, ErrInvalidOrExpiredToken)
		return
	}
	if err := core.ValidatePhone(target); err != nil {
		badRequest(w, ErrInvalidOrExpiredToken)
		return
	}
	target = core.NormalizePhone(target)

	if u, err := s.svc.GetUserByPhone(ctx, target); err == nil && u != nil {
		if u.PhoneVerified {
			sendErr(w, http.StatusConflict, ErrPhoneAlreadyVerified)
			return
		}
		sendErr(w, http.StatusGone, ErrVerificationLinkExpired)
		return
	}
	if pending, err := s.svc.GetPendingPhoneRegistrationByPhone(ctx, target); err == nil && pending != nil {
		badRequest(w, ErrInvalidOrExpiredToken)
		return
	}
	sendErr(w, http.StatusGone, ErrVerificationLinkExpired)
}
