package securitytest

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"sync"
	"testing"

	"github.com/open-rails/authkit"
	"github.com/open-rails/authkit/authtest"
	"github.com/open-rails/authkit/iam"
	"github.com/open-rails/authkit/internal/httpapi"
	"github.com/open-rails/authkit/internal/testidp"
	"github.com/stretchr/testify/require"
)

// newDevice is a browser's device cookie.
func newDevice() *http.Cookie {
	b := make([]byte, 32)
	_, _ = rand.Read(b)
	return &http.Cookie{Name: httpapi.CurrentCookie(httpapi.CookieDevice, true).Name, Value: base64.RawURLEncoding.EncodeToString(b)}
}

// signInFrom signs a in with its password from address, on device (nil: a
// client without a device cookie).
func (h *host) signInFrom(a account, address string, device *http.Cookie) response {
	h.t.Helper()
	req := request{method: http.MethodPost, path: "/password/login", header: from(address),
		body: map[string]string{"identifier": a.email, "password": password}}
	if device != nil {
		req.cookies = []*http.Cookie{device}
	}
	return h.do(req)
}

func requireSignedIn(t *testing.T, r response, why ...any) {
	t.Helper()
	require.Equal(t, http.StatusOK, r.status, append([]any{r.String()}, why...)...)
	require.Equal(t, httpapi.AuthComplete, authResult(t, r).Status, r.String())
}

// requireLimited: r is the sign-in limit's 429 code at limit, with when to
// retry: within the day the counts cover.
func requireLimited(t *testing.T, r response, code string, limit int) {
	t.Helper()
	require.Equal(t, http.StatusTooManyRequests, r.status, r.String())
	require.Equal(t, code, r.errorCode())
	retry, err := strconv.Atoi(r.header.Get("Retry-After"))
	require.NoError(t, err, "a 429 without Retry-After")
	require.Positive(t, retry)
	require.LessOrEqual(t, retry, 24*60*60)
	var env struct {
		Error struct {
			Metadata struct {
				Limit             int `json:"limit"`
				RetryAfterSeconds int `json:"retry_after_seconds"`
			} `json:"metadata"`
		} `json:"error"`
	}
	r.json(t, &env)
	require.Equal(t, limit, env.Error.Metadata.Limit)
	require.Equal(t, retry, env.Error.Metadata.RetryAfterSeconds)
}

// deviceStep requires r to be a sign-in waiting on a new device's code.
func deviceStep(t *testing.T, r response) httpapi.DeviceVerificationStep {
	t.Helper()
	res := authResult(t, r)
	require.Equal(t, httpapi.AuthDeviceVerificationRequired, res.Status, r.String())
	require.NotNil(t, res.DeviceVerification)
	return *res.DeviceVerification
}

func (h *host) confirmDevice(step httpapi.DeviceVerificationStep, code string, device *http.Cookie) response {
	h.t.Helper()
	return h.do(request{method: http.MethodPost, path: "/device-verification/confirm", cookies: []*http.Cookie{device},
		body: map[string]string{"user_id": step.UserID, "challenge": step.Challenge, "code": code}})
}

// TestSecuritySignInLimits: Config.SignIn's defaults (5 accounts per device,
// 20 per address without a device cookie, 10 new devices per account a day)
// hold on every replica and every way of signing in. Signing back into a
// counted account and a device the account knows are never limited; a new
// device past the limit proves itself with a code only the owner receives.
func TestSecuritySignInLimits(t *testing.T) {
	h := newHost(t, withHTTP(generousLimits), withHTTP(behindProxy), httpsFrontend,
		authtest.WithConfig(func(c *authkit.Config) { c.SignIn = authkit.SignInConfig{} }))

	t.Run("five accounts per device; switching between them stays allowed", func(t *testing.T) {
		device, address := newDevice(), "203.0.113.10"
		var accounts []account
		for i := range 6 {
			accounts = append(accounts, h.newAccount(fmt.Sprintf("dev%d", i)))
		}
		for _, a := range accounts[:5] {
			requireSignedIn(t, h.signInFrom(a, address, device))
		}
		requireSignedIn(t, h.signInFrom(accounts[0], address, device))
		requireSignedIn(t, h.signInFrom(accounts[3], address, device))
		requireLimited(t, h.signInFrom(accounts[5], address, device), "too_many_accounts", 5)
		requireSignedIn(t, h.signInFrom(accounts[4], address, device), "a refusal costs the counted accounts nothing")
		requireSignedIn(t, h.signInFrom(accounts[5], address, newDevice()), "another browser at the same address has its own count")
	})

	t.Run("a client without a device cookie counts by address, per /64, and is given one", func(t *testing.T) {
		var accounts []account
		for i := range 22 {
			accounts = append(accounts, h.newAccount(fmt.Sprintf("addr%d", i)))
		}
		first := h.signInFrom(accounts[0], "2001:db8:5::a", nil)
		requireSignedIn(t, first)
		var issued *http.Cookie
		for _, c := range first.cookies {
			if c.Name == httpapi.CurrentCookie(httpapi.CookieDevice, true).Name {
				issued = c
			}
		}
		require.NotNil(t, issued, "a client without a device cookie is issued one")
		require.True(t, issued.HttpOnly && issued.Secure && issued.SameSite == http.SameSiteLaxMode, "%+v", issued)
		require.Equal(t, "/", issued.Path)
		require.Positive(t, issued.MaxAge)
		for i, a := range accounts[1:20] {
			requireSignedIn(t, h.signInFrom(a, fmt.Sprintf("2001:db8:5::%x", 0xb+i%2), nil))
		}
		requireLimited(t, h.signInFrom(accounts[20], "2001:db8:5::ff", nil), "too_many_accounts", 20)
		requireSignedIn(t, h.signInFrom(accounts[20], "2001:db8:6::a", nil), "another /64 is another client")

		// The issued cookie carries on its browser's count: it began with
		// accounts[0], so four more fill it.
		for _, a := range accounts[1:5] {
			requireSignedIn(t, h.signInFrom(a, "198.51.100.7", &http.Cookie{Name: issued.Name, Value: issued.Value}))
		}
		requireLimited(t, h.signInFrom(accounts[21], "198.51.100.7", &http.Cookie{Name: issued.Name, Value: issued.Value}), "too_many_accounts", 5)
	})

	t.Run("past ten new devices a day, a new device enters a code sent to the owner", func(t *testing.T) {
		owner := h.newAccount("shared")
		var devices []*http.Cookie
		for i := range 10 {
			devices = append(devices, newDevice())
			requireSignedIn(t, h.signInFrom(owner, fmt.Sprintf("203.0.113.%d", 40+i), devices[i]))
		}
		eleventh := newDevice()
		step := deviceStep(t, h.signInFrom(owner, "203.0.113.60", eleventh))
		require.Equal(t, owner.id, step.UserID)
		require.Equal(t, "email", step.Channel)
		require.Equal(t, []string{"email"}, step.Channels)
		require.NotContains(t, step.Destination, owner.email, "the destination is masked")
		code := h.mail.Last(t, iam.MessageNewDeviceCode, owner.email).Code
		require.Len(t, code, 6)

		wrong := "000000"
		if code == wrong {
			wrong = "111111"
		}
		resp := h.confirmDevice(step, wrong, eleventh)
		require.Equal(t, http.StatusUnauthorized, resp.status, resp.String())
		require.Equal(t, "invalid_code", resp.errorCode())
		resp = h.post("/2fa/verify", map[string]string{"user_id": step.UserID, "challenge": step.Challenge, "code": code}, "")
		require.NotEqual(t, http.StatusOK, resp.status, "a device challenge is not a second factor: %s", resp)

		requireSignedIn(t, h.confirmDevice(step, code, eleventh))
		requireSignedIn(t, h.signInFrom(owner, "203.0.113.61", eleventh), "a confirmed device is known")
		requireSignedIn(t, h.signInFrom(owner, "203.0.113.62", devices[0]), "a known device is never challenged")

		// A resend replaces the code; the first one is spent with it.
		twelfth := newDevice()
		step = deviceStep(t, h.signInFrom(owner, "203.0.113.63", twelfth))
		first := h.mail.Last(t, iam.MessageNewDeviceCode, owner.email).Code
		resent := h.do(request{method: http.MethodPost, path: "/device-verification/send", cookies: []*http.Cookie{twelfth},
			body: map[string]string{"user_id": step.UserID, "challenge": step.Challenge, "channel": "email"}})
		require.Equal(t, step.Challenge, deviceStep(t, resent).Challenge)
		second := h.mail.Last(t, iam.MessageNewDeviceCode, owner.email).Code
		if first != second {
			require.Equal(t, http.StatusUnauthorized, h.confirmDevice(step, first, twelfth).status)
		}
		requireSignedIn(t, h.confirmDevice(step, second, twelfth))
	})

	t.Run("replicas share the counts, with no Redis", func(t *testing.T) {
		other := h.replica()
		device, address := newDevice(), "203.0.113.70"
		var accounts []account
		for i := range 6 {
			accounts = append(accounts, h.newAccount(fmt.Sprintf("rep%d", i)))
		}
		for i, a := range accounts[:5] {
			on := h
			if i%2 == 1 {
				on = other
			}
			requireSignedIn(t, on.signInFrom(a, address, device))
		}
		requireLimited(t, other.signInFrom(accounts[5], address, device), "too_many_accounts", 5)
		requireLimited(t, h.signInFrom(accounts[5], address, device), "too_many_accounts", 5)
	})

	t.Run("concurrent sign-ins never pass the limit", func(t *testing.T) {
		device, address := newDevice(), "203.0.113.80"
		var accounts []account
		for i := range 8 {
			accounts = append(accounts, h.newAccount(fmt.Sprintf("race%d", i)))
		}
		results := make([]response, len(accounts))
		var wg sync.WaitGroup
		for i, a := range accounts {
			wg.Go(func() {
				for {
					// The password-hashing budget may turn a burst away for a moment.
					if results[i] = h.signInFrom(a, address, device); results[i].status != http.StatusServiceUnavailable {
						return
					}
				}
			})
		}
		wg.Wait()
		var signedIn, refused int
		for _, r := range results {
			switch r.status {
			case http.StatusOK:
				requireSignedIn(t, r)
				signedIn++
			default:
				requireLimited(t, r, "too_many_accounts", 5)
				refused++
			}
		}
		require.Equal(t, 5, signedIn)
		require.Equal(t, 3, refused)
	})
}

// TestSecuritySignInLimitsEdges: with one account per device and one new
// device per account, registration and provider sign-ups count and create no
// account from a full device, a second factor stands in for the device code,
// and an account with no proven address cannot admit a new device at all.
func TestSecuritySignInLimitsEdges(t *testing.T) {
	idp := testidp.New(t)
	h := newHost(t, withHTTP(generousLimits), withHTTP(behindProxy), httpsFrontend, withProviders(idp.OIDC("idp")),
		authtest.WithConfig(func(c *authkit.Config) {
			c.SignIn = authkit.SignInConfig{AccountsPerDevice: 1, AccountsPerAddress: 1, NewDevicesPerAccount: 1}
		}))

	t.Run("a full device registers no account", func(t *testing.T) {
		device := newDevice()
		requireSignedIn(t, h.signInFrom(h.newAccount("full"), "203.0.113.90", device))
		name := unique("blocked")
		resp := h.do(request{method: http.MethodPost, path: "/register", header: from("203.0.113.90"), cookies: []*http.Cookie{device},
			body: map[string]string{"identifier": name + "@security.test", "username": name, "password": password}})
		requireLimited(t, resp, "too_many_accounts", 1)
		_, err := h.auth.User(t.Context(), iam.UserByEmail(name+"@security.test"))
		require.ErrorIs(t, err, iam.ErrUserNotFound)

		fresh := newDevice()
		resp = h.do(request{method: http.MethodPost, path: "/register", header: from("203.0.113.91"), cookies: []*http.Cookie{fresh},
			body: map[string]string{"identifier": name + "@security.test", "username": name, "password": password}})
		requireSignedIn(t, resp)
		requireLimited(t, h.signInFrom(h.newAccount("after"), "203.0.113.91", fresh), "too_many_accounts", 1)
	})

	t.Run("a provider sign-up counts against the device that began it", func(t *testing.T) {
		device := newDevice()
		requireSignedIn(t, h.signInFrom(h.newAccount("oidcfull"), "203.0.113.92", device))
		start := h.do(request{method: http.MethodGet, path: "//oidc/idp/login", header: from("203.0.113.92"), cookies: []*http.Cookie{device}})
		require.Equal(t, http.StatusFound, start.status, start.String())
		email := unique("oidc") + "@security.test"
		// The callback arrives without the device cookie, as a form_post does.
		resp := h.oidcCallback(idp, start, testidp.Identity{Subject: unique("sub"), Email: email, EmailVerified: true}, "callback", url.Values{"format": {"json"}})
		requireLimited(t, resp, "too_many_accounts", 1)
		_, err := h.auth.User(t.Context(), iam.UserByEmail(email))
		require.ErrorIs(t, err, iam.ErrUserNotFound)
	})

	t.Run("a second factor stands in for the device code", func(t *testing.T) {
		a := h.newAccount("mfa")
		h.enrollEmail2FA(a)
		for i, device := range []*http.Cookie{newDevice(), newDevice()} {
			resp := h.signInFrom(a, fmt.Sprintf("203.0.113.%d", 93+i), device)
			step := secondFactor(t, resp)
			resp = h.do(request{method: http.MethodPost, path: "/2fa/verify", cookies: []*http.Cookie{device},
				body: map[string]string{"user_id": a.id, "challenge": step.Challenge, "code": h.mail.Last(t, iam.MessageLoginCode, a.email).Code}})
			requireSignedIn(t, resp)
		}
		require.Empty(t, h.mail.Messages(iam.MessageNewDeviceCode, a.email))
	})

	t.Run("an account with no proven address admits no new device past the limit", func(t *testing.T) {
		name := unique("unproven")
		u, err := h.auth.CreateUser(t.Context(), iam.NewUser{Email: name + "@security.test", Username: name, Password: password})
		require.NoError(t, err)
		a := account{id: u.ID, email: name + "@security.test", username: name}
		known := newDevice()
		requireSignedIn(t, h.signInFrom(a, "203.0.113.95", known))
		requireLimited(t, h.signInFrom(a, "203.0.113.96", newDevice()), "too_many_devices", 1)
		requireSignedIn(t, h.signInFrom(a, "203.0.113.97", known), "its known device still signs in")
	})
}
