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
	if s.rateLimited(w, r, RLEmailVerifyRequest) {
		return
	}
	var req struct {
		Email string `json:"email"`
	}
	if err := decodeJSON(r, &req); err != nil {
		badRequest(w, ErrInvalidRequest)
		return
	}
	if err := core.ValidateEmail(req.Email); err != nil {
		badRequest(w, ErrorCode(core.ValidationErrorCode(err)))
		return
	}

	// Per-identifier check: prevents verification-mail bombing of a single
	// address from many IPs.
	if s.rateLimitedByIdentifier(w, r, RLEmailVerifyRequest, req.Email) {
		return
	}

	if !s.svc.HasEmailSender() {
		serverErr(w, ErrEmailVerificationUnavailable)
		return
	}
	if err := s.svc.RequestEmailVerification(r.Context(), req.Email, 0); err != nil {
		if s.handleDeliveryError(w, r, "email_verify_request", "send_email_verification", err) {
			return
		}
		if handleVerificationRequestError(w, err) {
			return
		}
		s.logInternalError(r, "email_verify_request", "request_email_verification", "verification_request_failed", err)
		serverErr(w, ErrVerificationRequestFailed)
		return
	}
	writeJSON(w, http.StatusAccepted, map[string]any{"ok": true})
}

func (s *Service) handleEmailVerifyConfirmPOST(w http.ResponseWriter, r *http.Request) {
	if s.rateLimited(w, r, RLEmailVerifyConfirm) {
		return
	}
	var req struct {
		Code       string `json:"code"`
		Token      string `json:"token"`
		Identifier string `json:"identifier"`
		Email      string `json:"email"`
	}
	if err := decodeJSON(r, &req); err != nil {
		badRequest(w, ErrInvalidRequest)
		return
	}
	if token := strings.TrimSpace(req.Token); token != "" {
		s.confirmEmailVerificationToken(w, r, token, req.Identifier, req.Email)
		return
	}

	// Typed 6-digit code path: the code is short, so it MUST be scoped to a
	// specific email and attempt-capped to be brute-force resistant. The code is
	// looked up globally by hash; without binding it to the supplied address a
	// guessed code would match (and take over) whichever account happens to hold
	// it, and a per-IP-only limit is trivially defeated by IP rotation (AK F1).
	code := strings.ToUpper(strings.TrimSpace(req.Code))
	email := strings.TrimSpace(req.Email)
	if email == "" {
		email = strings.TrimSpace(req.Identifier)
	}
	if code == "" || email == "" {
		badRequest(w, ErrInvalidRequest)
		return
	}
	if err := core.ValidateEmail(email); err != nil {
		badRequest(w, ErrorCode(core.ValidationErrorCode(err)))
		return
	}
	email = core.NormalizeEmail(email)

	// Per-identifier cap: a failed code is not consumed, so bound guesses against
	// one address even from many IPs.
	if s.rateLimitedByIdentifier(w, r, RLEmailVerifyConfirm, email) {
		return
	}

	// Try pending registration first (new flow), then existing-user verification.
	if userID, err := s.svc.ConfirmPendingRegistration(r.Context(), email, code); err == nil && userID != "" {
		s.svc.ClearEmailVerifyCodeAttempts(r.Context(), email)
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

	if userID, err := s.svc.ConfirmEmailVerification(r.Context(), email, code); err == nil && userID != "" {
		s.svc.ClearEmailVerifyCodeAttempts(r.Context(), email)
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

	// Both failed: count the bad guess and (after the cap) invalidate the code.
	s.svc.RecordFailedEmailVerifyCode(r.Context(), email)
	badRequest(w, ErrInvalidOrExpiredCode)
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
	sid, rt, _, err := s.svc.IssueRefreshSessionWithAuthMethods(r.Context(), userID, ua, ip, authMethodsForSessionMethod(method))
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

func authMethodsForSessionMethod(method string) []string {
	switch method {
	case "email_verification":
		return []string{"email"}
	case "phone_verification":
		return []string{"sms"}
	default:
		return []string{"pwd"}
	}
}
