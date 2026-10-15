package httpapi

import (
	"errors"
	"net/http"
	"strings"

	"github.com/open-rails/authkit/iam"
	"github.com/open-rails/authkit/internal/tenancy"
)

// A portal with no fixed/default tenant remembers only which independent
// directory it last signed into. The actual refresh secret remains mandatory
// and is checked against that directory's live account by the engine.
func (s *Service) activeTenantRefresh(r *http.Request, body string) (*http.Request, bool) {
	if _, err := s.svc.AccountScope(r.Context()); err == nil {
		return r, true
	} else if !errors.Is(err, iam.ErrTenantRequired) {
		return r, false
	}
	if _, cookie := refreshCookieEnabled(r); !cookie || strings.TrimSpace(body) != "" {
		return r, true
	}
	secure := s.cookieSecure(r)
	variants := []CookieVariant{CurrentCookie(CookieActiveTenant, secure), CurrentCookie(CookieActiveTenant, !secure)}
	for i := range variants {
		variants[i].Name = ActiveTenantCookieName(s.cfg.Token.Issuer, variants[i].Secure)
	}
	value, ok := refreshCookieCandidate(r, variants...)
	if !ok {
		return r, false
	}
	tenant, err := iam.ParseTenantID(value)
	if err != nil {
		return r, false
	}
	return r.WithContext(tenancy.With(r.Context(), tenant)), true
}

func (s *Service) setActiveTenantCookie(w http.ResponseWriter, r *http.Request) {
	scope, err := s.svc.AccountScope(r.Context())
	if err != nil {
		return
	}
	tenant, err := iam.ParseTenantID(scope.ID())
	if err != nil {
		return
	}
	secure := s.cookieSecure(r)
	current := CurrentCookie(CookieActiveTenant, secure)
	expireCookieVariants(w, r, CookieActiveTenant, &current, secure, func(v CookieVariant) string { return ActiveTenantCookieName(s.cfg.Token.Issuer, v.Secure) }, true)
	cookie := &http.Cookie{Name: ActiveTenantCookieName(s.cfg.Token.Issuer, secure), Value: tenant.String(), Path: current.Path, HttpOnly: true, Secure: secure, SameSite: http.SameSiteLaxMode}
	if duration := s.cfg.Token.RefreshTokenDuration; duration > 0 {
		cookie.MaxAge = int(duration.Seconds())
	}
	http.SetCookie(w, cookie)
}
