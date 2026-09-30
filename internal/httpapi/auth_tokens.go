package httpapi

import (
	"net/http"

	"github.com/open-rails/authkit/iam"
)

// Session-establishing responses (#313): every route hands out the same
// iam.TokenSet, as the whole body (writeTokenSet) or under "token_set" beside
// route-specific fields. The refresh token rides in the body unless the mount
// opted into the HttpOnly cookie (ak#271).

// deliverRefreshToken routes the refresh token to whichever transport this
// mount declared: with HTTPConfig.RefreshCookie on it moves to an HttpOnly
// cookie and leaves the envelope, so nothing downstream can leak it into a
// body, a URL fragment or a postMessage payload. EVERY session-establishing
// response goes through here.
func (s *Service) deliverRefreshToken(w http.ResponseWriter, r *http.Request, tokens iam.TokenSet) iam.TokenSet {
	if _, ok := refreshCookieEnabled(r); !ok || tokens.RefreshToken == nil {
		return tokens
	}
	s.setRefreshCookie(w, r, *tokens.RefreshToken)
	tokens.RefreshToken = nil
	return tokens
}

// writeTokenSet answers with the TokenSet as the whole body.
func (s *Service) writeTokenSet(w http.ResponseWriter, r *http.Request, status int, tokens iam.TokenSet) {
	writeJSON(w, status, s.deliverRefreshToken(w, r, tokens))
}
