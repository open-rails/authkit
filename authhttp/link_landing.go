package authhttp

import (
	"net/http"
	"net/url"
	"strings"
)

func (s *Service) handleEmailVerifyConfirmGET(w http.ResponseWriter, r *http.Request) {
	s.redirectLinkLanding(w, r, s.svc.Config().Frontend.VerifyPath, "email")
}

func (s *Service) handlePhoneVerifyConfirmGET(w http.ResponseWriter, r *http.Request) {
	s.redirectLinkLanding(w, r, s.svc.Config().Frontend.VerifyPath, "phone")
}

func (s *Service) handleEmailPasswordResetConfirmGET(w http.ResponseWriter, r *http.Request) {
	s.redirectLinkLanding(w, r, s.svc.Config().Frontend.PasswordResetPath, "email")
}

func (s *Service) handlePhonePasswordResetConfirmGET(w http.ResponseWriter, r *http.Request) {
	s.redirectLinkLanding(w, r, s.svc.Config().Frontend.PasswordResetPath, "phone")
}

// redirectLinkLanding hands the emailed/texted link token to the host SPA in
// the URL FRAGMENT (never the query: fragments are not sent to the server, do
// not land in access logs or Referer) with Cache-Control: no-store — the same
// shape browser_error.go uses for its token-bearing redirects (ak#324).
// Frontends read location.hash on VerifyPath / PasswordResetPath.
func (s *Service) redirectLinkLanding(w http.ResponseWriter, r *http.Request, frontendPath, channel string) {
	q := url.Values{}
	q.Set("status", "ready")
	q.Set("channel", channel)
	if token := strings.TrimSpace(r.URL.Query().Get("token")); token != "" {
		q.Set("token", token)
	} else {
		q.Set("status", "invalid_request")
	}
	if rt := sanitizeReturnTo(r.URL.Query().Get("return_to")); rt != "/" {
		q.Set("return_to", rt)
	}
	if strings.TrimSpace(frontendPath) == "" {
		frontendPath = "/"
	}
	target := strings.TrimRight(strings.TrimSpace(s.svc.Config().Frontend.BaseURL), "/") + frontendPath + "#" + q.Encode()
	w.Header().Set("Cache-Control", "no-store")
	http.Redirect(w, r, target, http.StatusFound)
}
