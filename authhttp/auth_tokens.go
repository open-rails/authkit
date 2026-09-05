package authhttp

import (
	"net/http"

	authkit "github.com/open-rails/authkit"
	authcore "github.com/open-rails/authkit/internal/authcore"
)

// Session-establishing responses (#313): every route hands out the same
// authkit.TokenSet — as the whole body (writeTokenSet) or under "token_set"
// beside route-specific fields (writeTokenSetWith). The refresh token rides in
// the body unless the mount opted into the HttpOnly cookie (ak#271).

func (s *Service) issueTokensForUser(w http.ResponseWriter, r *http.Request, userID string, method string) error {
	tokens, err := s.createTokensForUser(r, userID, method)
	if err != nil {
		return err
	}
	s.writeTokenSet(w, r, http.StatusOK, tokens)
	return nil
}

func (s *Service) createTokensForUser(r *http.Request, userID string, method string) (authkit.TokenSet, error) {
	session, err := s.svc.IssueLoginSession(r.Context(), authcore.LoginSessionInput{
		UserID: userID, AuthMethods: authMethodsForSessionMethod(method), Event: method,
		UserAgent: r.UserAgent(), IP: remoteIP(r),
	})
	if err != nil {
		return authkit.TokenSet{}, err
	}
	return session.TokenSet(), nil
}

// deliverRefreshToken routes the refresh token to whichever transport this
// mount declared: with MountOptions.RefreshCookie on it moves to an HttpOnly
// cookie and leaves the envelope, so nothing downstream can leak it into a
// body, a URL fragment or a postMessage payload. EVERY session-establishing
// response goes through here.
func (s *Service) deliverRefreshToken(w http.ResponseWriter, r *http.Request, tokens authkit.TokenSet) authkit.TokenSet {
	if _, ok := refreshCookieEnabled(r); !ok {
		return tokens
	}
	s.setRefreshCookie(w, r, tokens.RefreshToken)
	tokens.RefreshToken = ""
	return tokens
}

// writeTokenSet answers with the TokenSet as the whole body.
func (s *Service) writeTokenSet(w http.ResponseWriter, r *http.Request, status int, tokens authkit.TokenSet) {
	writeJSON(w, status, s.deliverRefreshToken(w, r, tokens))
}

// writeTokenSetWith answers {"token_set": ..., ...extra} — for routes whose
// response carries more than the session (created, return_to, user, ...).
func (s *Service) writeTokenSetWith(w http.ResponseWriter, r *http.Request, status int, tokens authkit.TokenSet, extra map[string]any) {
	body := map[string]any{"token_set": s.deliverRefreshToken(w, r, tokens)}
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
