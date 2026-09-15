package authhttp

import (
	"mime"
	"net/http"

	authkit "github.com/open-rails/authkit"
)

// guardJSONAPI runs before credentials, authorization or rate-limit budgets are
// consumed. Browser OIDC callbacks have their own state binding and form format.
func (s *Service) guardJSONAPI(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Body != nil && r.Body != http.NoBody {
			mediaType, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
			if err != nil || mediaType != "application/json" {
				badRequest(w, authkit.CodeInvalidRequest)
				return
			}
		}
		if _, cookies := refreshCookieEnabled(r); cookies && r.Method != http.MethodGet && r.Method != http.MethodHead && r.Method != http.MethodOptions && !s.cookieOriginAllowed(r) {
			badRequest(w, authkit.CodeInvalidRequest)
			return
		}
		next.ServeHTTP(w, r)
	})
}
