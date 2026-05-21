package authhttp

import (
	"net/http"
	"strings"
)

func (s *Service) handlePhoneVerifyConfirmLinkPOST(w http.ResponseWriter, r *http.Request) {
	if s.rateLimited(w, r, RLPhoneVerifyConfirm) {
		return
	}

	var req struct {
		Token string `json:"token"`
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

	badRequest(w, "invalid_or_expired_token")
}
