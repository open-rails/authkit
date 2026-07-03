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
	http.Redirect(w, r, buildFrontendURL(s.svc.Config().Frontend.BaseURL, frontendPath, q), http.StatusFound)
}

func buildFrontendURL(baseURL, frontendPath string, q url.Values) string {
	if strings.TrimSpace(frontendPath) == "" {
		frontendPath = "/"
	}
	target := strings.TrimRight(strings.TrimSpace(baseURL), "/") + frontendPath
	if encoded := q.Encode(); encoded != "" {
		if strings.Contains(frontendPath, "?") {
			target += "&" + encoded
		} else {
			target += "?" + encoded
		}
	}
	return target
}
