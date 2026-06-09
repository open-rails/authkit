package authhttp

import (
	"context"
	"net/http"
	"strings"

	core "github.com/open-rails/authkit/core"
)

func (s *Service) handlePhoneVerifyConfirmLinkPOST(w http.ResponseWriter, r *http.Request) {
	if s.rateLimited(w, r, RLPhoneVerifyConfirm) {
		return
	}

	var req struct {
		Token       string `json:"token"`
		Identifier  string `json:"identifier"`
		PhoneNumber string `json:"phone_number"`
	}
	if err := decodeJSON(r, &req); err != nil || strings.TrimSpace(req.Token) == "" {
		badRequest(w, "invalid_request")
		return
	}

	token := strings.TrimSpace(req.Token)
	if userID, err := s.svc.ConfirmPendingPhoneRegistrationByToken(r.Context(), token); err == nil && strings.TrimSpace(userID) != "" {
		if err := s.issueTokensForUser(w, r, userID, "phone_verification"); err != nil {
			serverErr(w, "token_issue_failed")
			return
		}
		return
	}
	if userID, err := s.svc.ConfirmPhoneVerificationByTokenUserID(r.Context(), token); err == nil && strings.TrimSpace(userID) != "" {
		if err := s.issueTokensForUser(w, r, userID, "phone_verification"); err != nil {
			serverErr(w, "token_issue_failed")
			return
		}
		return
	}

	s.handlePhoneVerifyLinkFailure(w, r.Context(), req.Identifier, req.PhoneNumber)
}

func (s *Service) handlePhoneVerifyLinkFailure(w http.ResponseWriter, ctx context.Context, identifier, phoneNumber string) {
	target := strings.TrimSpace(identifier)
	if target == "" {
		target = strings.TrimSpace(phoneNumber)
	}
	if target == "" {
		badRequest(w, "invalid_or_expired_token")
		return
	}
	if err := core.ValidatePhone(target); err != nil {
		badRequest(w, "invalid_or_expired_token")
		return
	}
	target = core.NormalizePhone(target)

	if u, err := s.svc.GetUserByPhone(ctx, target); err == nil && u != nil {
		if u.PhoneVerified {
			sendErr(w, http.StatusConflict, "phone_already_verified")
			return
		}
		sendErr(w, http.StatusGone, "verification_link_expired")
		return
	}
	if pending, err := s.svc.GetPendingPhoneRegistrationByPhone(ctx, target); err == nil && pending != nil {
		badRequest(w, "invalid_or_expired_token")
		return
	}
	sendErr(w, http.StatusGone, "verification_link_expired")
}
