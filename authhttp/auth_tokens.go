package authhttp

import (
	"net/http"
	"time"
)

type authTokensResponse struct {
	AccessToken string `json:"access_token"`
	TokenType   string `json:"token_type"`
	ExpiresIn   int64  `json:"expires_in"`
	// RefreshToken is omitted when MountOptions.RefreshCookie is on — the
	// token then rides an HttpOnly cookie instead of the body (ak#271).
	RefreshToken string `json:"refresh_token,omitempty"`
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
