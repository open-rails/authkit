package authhttp

import (
	"errors"
	"net"
	"net/http"
	"strings"
	"time"

	core "github.com/open-rails/authkit/core"
)

type authTokensResponse struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int64  `json:"expires_in"`
	RefreshToken string `json:"refresh_token"`
}

func (s *Service) handleEmailVerifyRequestPOST(w http.ResponseWriter, r *http.Request) {
	if !s.svc.HasEmailSender() {
		serverErr(w, "email_verification_unavailable")
		return
	}
	if s.rateLimited(w, r, RLEmailVerifyRequest) {
		return
	}
	var req struct {
		Email string `json:"email"`
	}
	if err := decodeJSON(r, &req); err != nil || strings.TrimSpace(req.Email) == "" {
		writeJSON(w, http.StatusOK, map[string]any{"ok": true})
		return
	}
	if err := s.svc.RequestEmailVerification(r.Context(), req.Email, 0); err != nil {
		if s.handleDeliveryError(w, r, "email_verify_request", "send_email_verification", err) {
			return
		}
		s.logInternalError(r, "email_verify_request", "request_email_verification", "verification_request_failed", err)
		serverErr(w, "verification_request_failed")
		return
	}
	writeJSON(w, http.StatusAccepted, map[string]any{"ok": true})
}

func (s *Service) handleEmailVerifyConfirmPOST(w http.ResponseWriter, r *http.Request) {
	if s.rateLimited(w, r, RLEmailVerifyConfirm) {
		return
	}
	var req struct {
		Code string `json:"code"`
	}
	if err := decodeJSON(r, &req); err != nil || strings.TrimSpace(req.Code) == "" {
		badRequest(w, "invalid_request")
		return
	}

	code := strings.ToUpper(strings.TrimSpace(req.Code))

	// Try pending registration first (new flow)
	userID, err := s.svc.ConfirmPendingRegistration(r.Context(), code)
	if err == nil && userID != "" {
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

	userID, err = s.svc.ConfirmEmailVerification(r.Context(), code)
	if err != nil {
		badRequest(w, "invalid_or_expired_code")
		return
	}
	if err := s.issueTokensForUser(w, r, userID, "email_verification"); err != nil {
		if errors.Is(err, core.ErrUserBanned) {
			unauthorized(w, "user_banned")
			return
		}
		serverErr(w, "token_issue_failed")
		return
	}
}

func (s *Service) issueTokensForUser(w http.ResponseWriter, r *http.Request, userID string, method string) error {
	tokens, err := s.createTokensForUser(r, userID, method)
	if err != nil {
		return err
	}

	writeJSON(w, http.StatusOK, tokens)
	return nil
}

func (s *Service) createTokensForUser(r *http.Request, userID string, method string) (authTokensResponse, error) {
	ua := r.UserAgent()
	ip := net.ParseIP(clientIP(r))
	sid, rt, _, err := s.svc.IssueRefreshSession(r.Context(), userID, ua, ip)
	if err != nil {
		return authTokensResponse{}, err
	}

	ipStr := clientIP(r)
	uaPtr, ipPtr := &ua, &ipStr
	s.svc.LogSessionCreated(r.Context(), userID, method, sid, ipPtr, uaPtr)

	accessToken, exp, err := s.svc.IssueAccessToken(r.Context(), userID, "", map[string]any{"sid": sid})
	if err != nil {
		return authTokensResponse{}, err
	}

	return authTokensResponse{
		AccessToken:  accessToken,
		TokenType:    "Bearer",
		ExpiresIn:    int64(time.Until(exp).Seconds()),
		RefreshToken: rt,
	}, nil
}
