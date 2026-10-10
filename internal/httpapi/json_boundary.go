package httpapi

import (
	"errors"
	"mime"
	"net/http"
	"strings"

	"github.com/open-rails/authkit/internal/authflow"
	"github.com/open-rails/authkit/internal/dpop"
	"github.com/open-rails/authkit/internal/errmodel"
	"github.com/open-rails/authkit/internal/jose"
)

// guardJSONAPI runs before credentials, authorization or rate-limit budgets are
// consumed. Browser OIDC callbacks have their own state binding and form format.
func (s *Service) guardJSONAPI(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Incoming HTTP framing identifies empty bodies even when host middleware
		// has wrapped http.NoBody (for example with MaxBytesReader).
		if r.ContentLength != 0 && r.Body != nil && r.Body != http.NoBody {
			mediaType, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
			if err != nil || mediaType != "application/json" {
				fail(w, errmodel.CodeUnsupportedMediaType)
				return
			}
		}
		if _, cookies := refreshCookieEnabled(r); cookies && r.Method != http.MethodGet && r.Method != http.MethodHead && r.Method != http.MethodOptions && !s.cookieOriginAllowed(r) {
			fail(w, errmodel.CodeOriginNotAllowed)
			return
		}
		r, ok := s.signInKey(w, r)
		if !ok {
			return
		}
		next.ServeHTTP(w, r)
	})
}

// signInKey verifies the DPoP proof of a request that presents no
// DPoP-bound token (a sign-in, a refresh), and records its key for the
// session the request issues or rotates (RFC 9449 §5). A proof for a bound
// token is the route's to verify. A proof that fails is refused.
func (s *Service) signInKey(w http.ResponseWriter, r *http.Request) (*http.Request, bool) {
	if len(r.Header.Values("DPoP")) == 0 {
		return r, true
	}
	if _, bound := jose.RequestToken(r); bound {
		return r, true
	}
	jkt, err := dpop.Verify(r, dpop.Check{URL: s.requestURL(r), Replay: s.replays.Claim})
	switch {
	case errors.Is(err, dpop.ErrReplayUnavailable):
		serverErr(w, "dpop_replay_unavailable", err)
		return r, false
	case err != nil:
		w.Header().Set("WWW-Authenticate", `DPoP error="invalid_dpop_proof", algs="ES256"`)
		fail(w, errmodel.CodeSenderProofRequired)
		return r, false
	}
	return r.WithContext(authflow.WithDPoPKey(r.Context(), jkt)), true
}

// requestURL is where clients reach r: HTTPConfig.PublicURL plus r's path
// beneath BasePath, the URL a DPoP proof names.
func (s *Service) requestURL(r *http.Request) string {
	return strings.TrimRight(s.http.PublicURL, "/") + strings.TrimPrefix(r.URL.EscapedPath(), strings.TrimRight(s.http.BasePath, "/"))
}
