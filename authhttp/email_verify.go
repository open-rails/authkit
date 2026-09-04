package authhttp

import (
	"github.com/open-rails/authkit/verify"
	"net/http"
	"strings"
	"time"

	"github.com/open-rails/authkit/embedded"
)

type authTokensResponse struct {
	AccessToken string `json:"access_token"`
	TokenType   string `json:"token_type"`
	ExpiresIn   int64  `json:"expires_in"`
	// RefreshToken is omitted when MountOptions.RefreshCookie is on — the
	// token then rides an HttpOnly cookie instead of the body (ak#271).
	RefreshToken string `json:"refresh_token,omitempty"`
}

func (s *Service) handleEmailVerifyRequestPOST(w http.ResponseWriter, r *http.Request) {
	if s.rateLimited(w, r, RLEmailVerifyRequest) {
		return
	}
	var req struct {
		Email    string `json:"email"`
		Password string `json:"password"`
	}
	if err := decodeJSON(r, &req); err != nil {
		badRequest(w, ErrInvalidRequest)
		return
	}
	email := strings.TrimSpace(req.Email)
	if err := embedded.ValidateEmail(email); err != nil {
		badRequest(w, ErrorCode(embedded.ValidationErrorCode(err)))
		return
	}
	email = embedded.NormalizeEmail(email)

	// Per-identifier check: prevents verification-mail bombing of a single
	// address from many IPs.
	if s.rateLimitedByIdentifier(w, r, RLEmailVerifyRequest, email) {
		return
	}

	if !s.svc.HasEmailSender() {
		serverErr(w, ErrEmailVerificationUnavailable)
		return
	}

	if claims, ok := verify.ClaimsFromContext(r.Context()); ok && claims.UserID != "" {
		if s.rateLimited(w, r, RLUserEmailChangeRequest) {
			return
		}
		ok, authMeta := s.requireFreshAuthOrPassword(w, r, claims, req.Password)
		if !ok {
			return
		}
		if err := s.svc.RequestEmailChange(r.Context(), claims.UserID, email); err != nil {
			if s.handleDeliveryError(w, r, "user_email_change_request", "send_email_verification", err) {
				return
			}
			if code := ErrorCode(embedded.ValidationErrorCode(err)); code != "" {
				badRequest(w, code)
				return
			}
			mapContactChangeError(w, err, ErrEmailUnchanged, ErrEmailInUse, ErrFailedToRequestEmailChange)
			return
		}
		resp := map[string]any{"ok": true, "message": "Verification sent to new email address"}
		for k, v := range authMeta {
			resp[k] = v
		}
		writeJSON(w, http.StatusAccepted, resp)
		return
	}

	if err := s.svc.RequestEmailVerification(r.Context(), email, 0); err != nil {
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

	// Typed 6-digit code path: the code is short, so it is only ever checked
	// against the record issued for the supplied email and attempt-capped per
	// identifier (a per-IP-only limit is trivially defeated by IP rotation).
	code := strings.ToUpper(strings.TrimSpace(req.Code))
	email := firstTrimmedNonEmpty(req.Email, req.Identifier)
	if code == "" || email == "" {
		badRequest(w, ErrInvalidRequest)
		return
	}
	if err := embedded.ValidateEmail(email); err != nil {
		badRequest(w, ErrorCode(embedded.ValidationErrorCode(err)))
		return
	}
	email = embedded.NormalizeEmail(email)

	// Per-identifier cap: a failed code is not consumed, so bound guesses against
	// one address even from many IPs.
	if s.rateLimitedByIdentifier(w, r, RLEmailVerifyConfirm, email) {
		return
	}

	// Try pending registration first (new flow), then existing-user verification.
	// A backend failure on any path is a 500 and is never counted as a guess.
	userID, err := s.svc.ConfirmPendingRegistration(r.Context(), email, code)
	if err == nil && userID != "" {
		s.svc.ClearEmailVerifyCodeAttempts(r.Context(), email)
		s.issueVerificationTokens(w, r, userID, "email_verification")
		return
	}
	if s.confirmBackendFailed(w, r, "email_verify_confirm", "confirm_pending_registration", err) {
		return
	}
	userID, err = s.svc.ConfirmEmailVerification(r.Context(), email, code)
	if err == nil && userID != "" {
		s.svc.ClearEmailVerifyCodeAttempts(r.Context(), email)
		s.issueVerificationTokens(w, r, userID, "email_verification")
		return
	}
	if s.confirmBackendFailed(w, r, "email_verify_confirm", "confirm_email_verification", err) {
		return
	}
	if claims, ok := verify.ClaimsFromContext(r.Context()); ok && claims.UserID != "" {
		err := s.svc.ConfirmEmailChange(r.Context(), claims.UserID, email, code, keepSession(claims))
		if err == nil {
			s.svc.ClearEmailVerifyCodeAttempts(r.Context(), email)
			writeJSON(w, http.StatusOK, map[string]any{"ok": true, "message": "Email changed successfully"})
			return
		}
		if s.confirmBackendFailed(w, r, "email_verify_confirm", "confirm_email_change", err) {
			return
		}
	}

	// Every path failed on the code itself: count the bad guess and (after the
	// cap) invalidate the code.
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
	ip := parseIP(remoteIP(r))
	sid, rt, _, err := s.svc.IssueRefreshSessionWithAuthMethods(r.Context(), userID, ua, ip, authMethodsForSessionMethod(method))
	if err != nil {
		return authTokensResponse{}, err
	}

	ipStr := remoteIP(r)
	uaPtr, ipPtr := &ua, &ipStr
	s.svc.LogSessionCreated(r.Context(), userID, method, sid, ipPtr, uaPtr)

	accessToken, exp, err := s.svc.MintAccessToken(r.Context(), userID, map[string]any{"sid": sid})
	if err != nil {
		return authTokensResponse{}, err
	}

	return newAuthTokens(accessToken, rt, exp), nil
}

// newAuthTokens builds the canonical OAuth-style token-pair envelope from a
// freshly issued access token: token_type is always "Bearer" and expires_in is
// derived from the access token's expiry.
func newAuthTokens(access, refresh string, exp time.Time) authTokensResponse {
	return authTokensResponse{
		AccessToken:  access,
		TokenType:    "Bearer",
		ExpiresIn:    int64(time.Until(exp).Seconds()),
		RefreshToken: refresh,
	}
}

// deliverRefreshToken routes the refresh token to whichever transport this
// mount declared. With MountOptions.RefreshCookie on it moves to an HttpOnly
// cookie and leaves the envelope, so nothing downstream can leak it into a
// body, a URL fragment or a postMessage payload; otherwise the envelope is
// returned untouched. EVERY session-establishing response goes through here.
func (s *Service) deliverRefreshToken(w http.ResponseWriter, r *http.Request, tokens authTokensResponse) authTokensResponse {
	if _, ok := refreshCookieEnabled(r); !ok {
		return tokens
	}
	s.setRefreshCookie(w, r, tokens.RefreshToken)
	tokens.RefreshToken = ""
	return tokens
}

// writeAccessTokenJSON marshals the token-pair envelope (the four §6.3 fields)
// plus any extra top-level fields (e.g. return_to, created, user) at the given
// status — replacing the hand-built map[string]any literals scattered across the
// session-establishing handlers.
func (s *Service) writeAccessTokenJSON(w http.ResponseWriter, r *http.Request, status int, tokens authTokensResponse, extra map[string]any) {
	tokens = s.deliverRefreshToken(w, r, tokens)
	if len(extra) == 0 {
		writeJSON(w, status, tokens)
		return
	}
	body := map[string]any{
		"access_token": tokens.AccessToken,
		"token_type":   tokens.TokenType,
		"expires_in":   tokens.ExpiresIn,
	}
	if tokens.RefreshToken != "" {
		body["refresh_token"] = tokens.RefreshToken
	}
	for k, v := range extra {
		body[k] = v
	}
	writeJSON(w, status, body)
}

func authMethodsForSessionMethod(method string) []string {
	switch method {
	case "email_verification", "passwordless_email":
		return []string{"email"}
	case "phone_verification", "passwordless_sms":
		return []string{"sms"}
	default:
		return []string{"pwd"}
	}
}
