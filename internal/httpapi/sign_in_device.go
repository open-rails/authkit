package httpapi

// The device cookie names a browser for Config.SignIn's limits: random,
// HttpOnly, SameSite=Lax, granting nothing. The engine sees only its hash. A
// client without one is known by its address (an IPv6 /64), and is issued one
// for next time. On HTTPS it is issued twice: also SameSite=None and
// Partitioned (CHIPS), the one a sign-in inside a third-party iframe sends
// back, so that iframe is recognized again under the same top-level site.

import (
	"encoding/base64"
	"net/http"
	"strings"
	"time"

	"github.com/open-rails/authkit/iam"
	"github.com/open-rails/authkit/internal/authflow"
	"github.com/open-rails/authkit/internal/secret"
)

// deviceCookieMaxAge is the longest lifetime browsers keep.
const deviceCookieMaxAge = 400 * 24 * time.Hour

// countsDevices reports whether sign-ins need their device: a sign-in limit
// is on, or phone-only accounts can exist (an SMS sender), whose every new
// device proves the phone again.
func (s *Service) countsDevices() bool {
	c := s.cfg.SignIn
	return c.AccountsPerDevice > 0 || c.AccountsPerAddress > 0 || c.NewDevicesPerAccount > 0 || s.smsSender
}

// signsIn reports whether the route signs in (it answers an AuthResult) or
// begins a browser sign-in. A provider callback is not one: its device is the
// one its flow began on, since a form_post callback arrives without the
// browser's SameSite cookies.
func (r RouteSpec) signsIn() bool {
	if r.Surface == SurfaceOIDC && strings.HasSuffix(r.Path, "/callback") {
		return false
	}
	if r.Group == iam.RouteBrowserOIDC {
		return true
	}
	for _, reply := range r.Responses {
		if _, ok := reply.Body.(AuthResult); ok {
			return true
		}
	}
	return false
}

// withSignInDevice attaches the request's device to its context.
func (s *Service) withSignInDevice(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		next.ServeHTTP(w, r.WithContext(authflow.WithSignInDevice(r.Context(), s.signInDevice(w, r))))
	})
}

// withClientAddress attaches the request's rate-limit address for the
// engine's own limits (text messages).
func (s *Service) withClientAddress(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		next.ServeHTTP(w, r.WithContext(authflow.WithClientAddress(r.Context(), s.addressKey(r))))
	})
}

// signInDevice is the request's device cookie, else its address, issuing the
// cookie it lacks.
func (s *Service) signInDevice(w http.ResponseWriter, r *http.Request) authflow.SignInDevice {
	secure := s.cookieSecure(r)
	current := CurrentCookie(CookieDevice, secure)
	if v, ok := deviceCookieValue(r, current.Name); ok {
		return authflow.SignInDevice{ID: "cookie:" + secret.Hash(v)}
	}
	if secure {
		if v, ok := deviceCookieValue(r, CurrentCookie(CookieDevicePartitioned, true).Name); ok {
			return authflow.SignInDevice{ID: "cookie:" + secret.Hash(v)}
		}
	}
	var d authflow.SignInDevice
	if ip := strings.TrimSpace(s.requestIP(r)); ip != "" {
		d.ID = "ip:" + rateLimitAddress(ip)
	}
	value := secret.Token(32)
	expireCookieVariants(w, r, CookieDevice, &current, secure, variantName, true)
	http.SetCookie(w, &http.Cookie{Name: current.Name, Value: value, Path: "/", MaxAge: int(deviceCookieMaxAge.Seconds()),
		HttpOnly: true, Secure: secure, SameSite: http.SameSiteLaxMode})
	if secure {
		http.SetCookie(w, &http.Cookie{Name: CurrentCookie(CookieDevicePartitioned, true).Name, Value: value, Path: "/", MaxAge: int(deviceCookieMaxAge.Seconds()),
			HttpOnly: true, Secure: true, SameSite: http.SameSiteNoneMode, Partitioned: true})
	}
	d.Issued = "cookie:" + secret.Hash(value)
	return d
}

// deviceCookieValue is the request's one well-formed device cookie.
func deviceCookieValue(r *http.Request, name string) (string, bool) {
	var values []string
	for _, c := range r.Cookies() {
		if c.Name == name {
			values = append(values, c.Value)
		}
	}
	if len(values) != 1 {
		return "", false
	}
	raw, err := base64.RawURLEncoding.DecodeString(values[0])
	return values[0], err == nil && len(raw) == 32
}
