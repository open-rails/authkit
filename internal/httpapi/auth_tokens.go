package httpapi

import (
	"net/http"

	"github.com/open-rails/authkit/iam"
)

// deliverRefreshToken routes the refresh token to whichever transport this
// mount declared: with HTTPConfig.RefreshCookie on it moves to an HttpOnly
// cookie and leaves the TokenSet, so nothing downstream can leak it into a
// body, a stored browser result or a postMessage payload (ak#271). Every
// AuthResult's session goes through here (authResult).
func (s *Service) deliverRefreshToken(w http.ResponseWriter, r *http.Request, tokens iam.TokenSet) iam.TokenSet {
	if _, ok := refreshCookieEnabled(r); !ok || tokens.RefreshToken == nil {
		return tokens
	}
	s.setRefreshCookie(w, r, *tokens.RefreshToken)
	tokens.RefreshToken = nil
	return tokens
}
