package securitytest

import (
	"bytes"
	"context"
	"crypto"
	"fmt"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/open-rails/authkit"
	"github.com/open-rails/authkit/authtest"
	"github.com/open-rails/authkit/iam"
	"github.com/open-rails/authkit/internal/testdb"
	"github.com/open-rails/authkit/internal/testkeys"
	"github.com/open-rails/authkit/keys"
	"github.com/stretchr/testify/require"
)

// TestSecurityMultiReplicaStores: codes, tokens and attempt budgets live in
// Postgres, so every replica shares them; rate-limit budgets are shared
// through Redis.
func TestSecurityMultiReplicaStores(t *testing.T) {
	t.Run("a reset token issued on one replica is spent once on any", func(t *testing.T) {
		one := newHost(t, withHTTP(generousLimits))
		two := one.replica()
		a := one.newAccount("replica-reset")
		require.Less(t, one.post("/password/reset/request", map[string]string{"identifier": a.email}, "").status, 300)
		token := one.mail.Last(t, iam.MessagePasswordReset, a.email).Token
		body := map[string]string{"token": token, "new_password": "Replica-reset-passphrase-4"}
		resp := two.post("/password/reset/confirm", body, "")
		require.Less(t, resp.status, 300, resp.String())
		replay := one.post("/password/reset/confirm", body, "")
		require.GreaterOrEqual(t, replay.status, 400, replay.String())
	})

	t.Run("second-factor guesses are budgeted across replicas", func(t *testing.T) {
		one := newHost(t, withHTTP(behindProxy), withHTTP(generousLimits))
		two := one.replica()
		a := one.newAccount("replica-mfa")
		one.enrollEmail2FA(a)
		ch := one.passwordStep(a, "198.51.100.30")
		code := one.mail.Last(t, iam.MessageLoginCode, a.email).Code
		for i := range 5 {
			h := []*host{one, two}[i%2]
			resp := h.secondStep(a, ch, wrongCode(code), fmt.Sprintf("203.0.113.%d", 100+i))
			require.Equal(t, http.StatusUnauthorized, resp.status, resp.String())
		}
		resp := two.secondStep(a, ch, code, "203.0.113.200")
		require.Equal(t, http.StatusUnauthorized, resp.status, "misses on another replica did not count: %s", resp)
	})

	t.Run("Redis budgets are shared by every replica", func(t *testing.T) {
		rdb := testdb.ScratchRedis(t)
		one := newHost(t, withHTTP(func(c *authkit.HTTPConfig) {
			c.RateLimits = map[string]authkit.RateLimit{"password_login": {Limit: 3, Window: time.Hour}}
		}), authtest.WithDeps(func(d *authkit.Deps) { d.Redis = rdb }))
		two := one.replica()
		a := one.newAccount("replicas")
		for i, h := range []*host{one, two, one} {
			resp := h.post("/password/login", map[string]string{"identifier": a.email, "password": "wrong-" + password}, "")
			require.Equal(t, http.StatusUnauthorized, resp.status, "attempt %d: %s", i, resp)
		}
		resp := two.post("/password/login", map[string]string{"identifier": a.email, "password": "wrong-" + password}, "")
		require.Equal(t, http.StatusTooManyRequests, resp.status, "second replica kept its own budget: %s", resp)
	})
}

// TestSecurityPasswordLimitIsPerAddress: passwords are high-entropy secrets,
// so password checks are limited per client address only. A stranger's wrong
// guesses cannot lock the owner out, the guessing address stays blocked even
// with the right password, and IPv6 clients are limited per /64.
func TestSecurityPasswordLimitIsPerAddress(t *testing.T) {
	h := newHost(t, withHTTP(behindProxy), withHTTP(func(c *authkit.HTTPConfig) {
		c.RateLimits = map[string]authkit.RateLimit{"password_login": {Limit: 3, Window: time.Hour}}
	}))
	a := h.newAccount("peraddress")
	attempt := func(ip, pass string) response {
		return h.do(request{method: http.MethodPost, path: "/password/login", header: from(ip),
			body: map[string]string{"identifier": a.email, "password": pass}})
	}
	for range 3 {
		resp := attempt("203.0.113.40", "wrong-"+password)
		require.Equal(t, http.StatusUnauthorized, resp.status, resp.String())
	}
	resp := attempt("203.0.113.40", password)
	require.Equal(t, http.StatusTooManyRequests, resp.status, "the guessing address kept its budget: %s", resp)
	resp = attempt("198.51.100.40", password)
	require.Equal(t, http.StatusOK, resp.status, "a stranger's wrong guesses locked the owner out: %s", resp)

	t.Run("IPv6 clients share one budget per /64", func(t *testing.T) {
		for i := range 3 {
			resp := attempt(fmt.Sprintf("2001:db8:40:1::%x", i+1), "wrong-"+password)
			require.Equal(t, http.StatusUnauthorized, resp.status, resp.String())
		}
		resp := attempt("2001:db8:40:1:ffff:ffff:ffff:ffff", password)
		require.Equal(t, http.StatusTooManyRequests, resp.status, "another address in the /64 got a fresh budget: %s", resp)
		resp = attempt("2001:db8:40:2::1", password)
		require.Equal(t, http.StatusOK, resp.status, resp.String())
	})
}

// TestSecurityClientAddressSpoofing: with no declared proxy, forwarding headers
// are attacker input and must not create fresh per-address budgets.
func TestSecurityClientAddressSpoofing(t *testing.T) {
	h := newHost(t, withHTTP(func(c *authkit.HTTPConfig) {
		c.RateLimits = map[string]authkit.RateLimit{"password_login": {Limit: 3, Window: time.Hour}}
	}))
	for i := range 4 {
		resp := h.do(request{method: http.MethodPost, path: "/password/login",
			header: http.Header{"X-Forwarded-For": {"203.0.113." + string(rune('1'+i))}, "Cf-Connecting-Ip": {"198.51.100." + string(rune('1'+i))}, "X-Real-Ip": {"192.0.2.9"}},
			body:   map[string]string{"identifier": unique("nobody") + "@security.test", "password": "wrong-" + password}})
		if i < 3 {
			require.Equal(t, http.StatusUnauthorized, resp.status, resp.String())
		} else {
			require.Equal(t, http.StatusTooManyRequests, resp.status, "a forged forwarding header reset the budget: %s", resp)
		}
	}
}

// TestSecurityForwardedForReadsEveryLine: a declared proxy that appends its
// own X-Forwarded-For line (HAProxy's option forwardfor) leaves the client's
// line in front of it. Every line counts, walked right to left, so a client
// cannot pick its own budget through the proxy.
func TestSecurityForwardedForReadsEveryLine(t *testing.T) {
	h := newHost(t, withHTTP(behindProxy), withHTTP(func(c *authkit.HTTPConfig) {
		c.RateLimits = map[string]authkit.RateLimit{"password_login": {Limit: 3, Window: time.Hour}}
	}))
	for i := range 4 {
		resp := h.do(request{method: http.MethodPost, path: "/password/login",
			header: http.Header{"X-Forwarded-For": {fmt.Sprintf("198.51.100.%d", i+1), "203.0.113.60"}},
			body:   map[string]string{"identifier": unique("nobody") + "@security.test", "password": "wrong-" + password}})
		if i < 3 {
			require.Equal(t, http.StatusUnauthorized, resp.status, resp.String())
		} else {
			require.Equal(t, http.StatusTooManyRequests, resp.status, "the client's own line picked its budget: %s", resp)
		}
	}
}

type rotatingKeys struct {
	current atomic.Pointer[keys.Static]
}

func (r *rotatingKeys) ActiveSigner() keys.Signer { return r.current.Load().ActiveSigner() }
func (r *rotatingKeys) PublicKeys() map[string]crypto.PublicKey {
	return r.current.Load().PublicKeys()
}

// TestSecurityKeyRotationIsPublished: removing a compromised signing key must
// stop both local acceptance and its publication to remote verifiers, and a new
// key must be published without a restart.
func TestSecurityKeyRotationIsPublished(t *testing.T) {
	old := signer()
	next := testkeys.RSA("security-kid-2")
	rotating := &rotatingKeys{}
	oldKeys, nextKeys := testkeys.Source(old), testkeys.Source(next)
	rotating.current.Store(&oldKeys)
	h := newHost(t, withHTTP(generousLimits), authtest.WithDeps(func(d *authkit.Deps) { d.KeySource = rotating }))
	a := h.newAccount("rotation")
	compromised := h.login(a).AccessToken
	kids := func() []string {
		resp := h.get("//.well-known/jwks.json", "")
		require.Equal(t, http.StatusOK, resp.status, resp.String())
		var doc keys.JWKS
		resp.json(t, &doc)
		var out []string
		for _, k := range doc.Keys {
			out = append(out, k.Kid)
		}
		return out
	}
	require.Equal(t, []string{old.KID()}, kids())
	rotating.current.Store(&nextKeys)
	require.Equal(t, []string{next.KID()}, kids(), "JWKS still publishes the removed key")
	require.Equal(t, http.StatusUnauthorized, h.get("/me", compromised).status)
	require.Equal(t, http.StatusOK, h.get("/me", h.login(a).AccessToken).status)
}

// TestSecurityRefreshCookieCSRF: a cross-site page must not spend or plant the
// browser's refresh cookie. On HTTPS the cookie is __Host- prefixed (Secure,
// host-only, Path=/), so a sibling subdomain can only plant the bare name; that
// name is read only alone, as the HTTP scheme's cookie
// (TestSecurityRefreshCookieUpgrade).
func TestSecurityRefreshCookieCSRF(t *testing.T) {
	h := newHost(t, withHTTP(generousLimits), withHTTP(func(c *authkit.HTTPConfig) { c.RefreshCookie = true }),
		authtest.WithConfig(func(c *authkit.Config) { c.Frontend.BaseURL = "https://app.security.test" }))
	a := h.newAccount("cookie")
	login := func(header http.Header) response {
		return h.do(request{method: http.MethodPost, path: "/password/login", header: header,
			body: map[string]string{"identifier": a.email, "password": password}})
	}
	var jar *http.Cookie
	for _, c := range login(nil).cookies {
		if c.Name == iam.RefreshCookieName {
			jar = c
		}
	}
	require.NotNil(t, jar, "no __Host- refresh cookie")
	require.Equal(t, "__Host-authkit_rt", jar.Name)
	require.True(t, jar.Secure)
	require.Equal(t, "/", jar.Path)
	require.Empty(t, jar.Domain)
	refresh := func(header http.Header, cookies ...*http.Cookie) response {
		return h.do(request{method: http.MethodPost, path: "/token", header: header, cookies: cookies,
			body: map[string]string{"grant_type": "refresh_token"}})
	}
	for _, tc := range []struct {
		name    string
		header  http.Header
		cookies []*http.Cookie
	}{
		{"cross-site fetch metadata", http.Header{"Sec-Fetch-Site": {"cross-site"}}, []*http.Cookie{jar}},
		{"same-site sibling", http.Header{"Sec-Fetch-Site": {"same-site"}}, []*http.Cookie{jar}},
		{"foreign Origin", http.Header{"Origin": {"https://evil.test"}}, []*http.Cookie{jar}},
		{"opaque Origin", http.Header{"Origin": {"null"}}, []*http.Cookie{jar}},
		{"tossed duplicate cookie", nil, []*http.Cookie{jar, {Name: iam.RefreshCookieName, Value: "attacker"}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			resp := refresh(tc.header, tc.cookies...)
			require.GreaterOrEqual(t, resp.status, 400, resp.String())
			require.NotContains(t, resp.String(), "access_token")
		})
	}
	t.Run("body refresh token is refused on a cookie mount", func(t *testing.T) {
		resp := h.post("/token", map[string]string{"grant_type": "refresh_token", "refresh_token": jar.Value}, "")
		require.GreaterOrEqual(t, resp.status, 400, resp.String())
	})
	t.Run("cross-site login plants no cookie", func(t *testing.T) {
		resp := login(http.Header{"Origin": {"https://evil.test"}, "Sec-Fetch-Site": {"cross-site"}})
		for _, c := range resp.cookies {
			require.NotEqual(t, iam.RefreshCookieName, c.Name)
		}
	})
	t.Run("control: same-origin refresh", func(t *testing.T) {
		resp := refresh(http.Header{"Sec-Fetch-Site": {"same-origin"}}, jar)
		require.Equal(t, http.StatusOK, resp.status, resp.String())
	})
}

// TestSecurityRefreshCookieUpgrade: a browser holding the other scheme's
// refresh cookie stays signed in when a deployment moves to HTTPS. One refresh
// reads it, reissues the current cookie and expires the other; sign-out clears
// every variant. Same-path duplicates are refused.
func TestSecurityRefreshCookieUpgrade(t *testing.T) {
	for _, tc := range []struct {
		name string
		jar  func(valid string) []*http.Cookie
	}{
		{"the plain cookie alone", func(valid string) []*http.Cookie {
			return []*http.Cookie{{Name: "authkit_rt", Value: valid}}
		}},
		{"a stale plain cookie beside the current one", func(valid string) []*http.Cookie {
			return []*http.Cookie{{Name: "authkit_rt", Value: "stale-plain"}, {Name: "__Host-authkit_rt", Value: valid}}
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := newHost(t, withHTTP(generousLimits), withHTTP(func(c *authkit.HTTPConfig) { c.RefreshCookie = true }),
				authtest.WithConfig(func(c *authkit.Config) { c.Frontend.BaseURL = "https://app.security.test" }))
			a := h.newAccount("upgrade")
			login := h.post("/password/login", map[string]string{"identifier": a.email, "password": password}, "")
			require.Equal(t, http.StatusOK, login.status, login.String())
			valid := cookieNamed(login.cookies, "__Host-authkit_rt", "/")
			require.NotNil(t, valid, "login set no __Host-authkit_rt cookie")

			resp := h.do(request{method: http.MethodPost, path: "/token", cookies: tc.jar(valid.Value),
				body: map[string]string{"grant_type": "refresh_token"}})
			require.Equal(t, http.StatusOK, resp.status, "the browser was signed out: %s", resp)
			require.Contains(t, resp.String(), "access_token")
			next := cookieNamed(resp.cookies, "__Host-authkit_rt", "/")
			require.NotNil(t, next, "the current cookie was not reissued")
			require.NotEmpty(t, next.Value)
			plain := cookieNamed(resp.cookies, "authkit_rt", "/")
			require.NotNil(t, plain, "the plain cookie was not expired")
			require.Less(t, plain.MaxAge, 0)

			access := session(t, resp)
			require.Empty(t, access.RefreshToken, "the cookie carries the refresh token")
			out := h.do(request{method: http.MethodDelete, path: "/logout", token: access.AccessToken, cookies: []*http.Cookie{next}})
			require.Less(t, out.status, 300, out.String())
			for _, name := range []string{"authkit_rt", "__Host-authkit_rt"} {
				c := cookieNamed(out.cookies, name, "/")
				require.NotNil(t, c, "sign-out left %s", name)
				require.Less(t, c.MaxAge, 0)
			}
		})
	}
	t.Run("a browser with no refresh cookie is simply signed out", func(t *testing.T) {
		h := newHost(t, withHTTP(generousLimits), withHTTP(func(c *authkit.HTTPConfig) { c.RefreshCookie = true }))
		resp := h.do(request{method: http.MethodPost, path: "/token", body: map[string]string{"grant_type": "refresh_token"}})
		require.Equal(t, http.StatusUnauthorized, resp.status, resp.String())
		require.Equal(t, "no_session", resp.errorCode())
	})
	t.Run("same-path duplicates are refused", func(t *testing.T) {
		h := newHost(t, withHTTP(generousLimits), withHTTP(func(c *authkit.HTTPConfig) { c.RefreshCookie = true }),
			authtest.WithConfig(func(c *authkit.Config) { c.Frontend.BaseURL = "http://app.security.test" }))
		a := h.newAccount("upgradedup")
		login := h.post("/password/login", map[string]string{"identifier": a.email, "password": password}, "")
		valid := cookieNamed(login.cookies, "authkit_rt", "/")
		require.NotNil(t, valid)
		resp := h.do(request{method: http.MethodPost, path: "/token", body: map[string]string{"grant_type": "refresh_token"},
			cookies: []*http.Cookie{{Name: "authkit_rt", Value: "a"}, {Name: "authkit_rt", Value: valid.Value}}})
		require.GreaterOrEqual(t, resp.status, 400, resp.String())
		require.NotContains(t, resp.String(), "access_token")
	})
}

func cookieNamed(cookies []*http.Cookie, name, path string) *http.Cookie {
	for _, c := range cookies {
		if c.Name == name && c.Path == path {
			return c
		}
	}
	return nil
}

// TestSecurityRequestBoundary covers hostile request shapes: oversized and
// malformed bodies, CORS reflection and internal detail in errors.
func TestSecurityRequestBoundary(t *testing.T) {
	h := newHost(t, withHTTP(generousLimits))
	for _, tc := range []struct {
		name string
		body string
	}{
		{"oversized body", `{"identifier":"` + strings.Repeat("a", 2<<20) + `","password":"x"}`},
		{"unknown field", `{"identifier":"a@b.test","password":"x","is_admin":true}`},
		{"trailing document", `{"identifier":"a@b.test","password":"x"}{"identifier":"b"}`},
		{"not JSON", `identifier=a&password=b`},
		{"SQL metacharacters", `{"identifier":"' OR 1=1; DROP TABLE users; --","password":"x"}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			resp := h.post("/password/login", tc.body, "")
			require.GreaterOrEqual(t, resp.status, 400, resp.String())
			require.Less(t, resp.status, 500, resp.String())
			lower := strings.ToLower(resp.String())
			for _, leak := range []string{"sql", "pgx", "postgres", "panic", "goroutine", "relation"} {
				require.NotContains(t, lower, leak)
			}
		})
	}
	t.Run("no CORS reflection", func(t *testing.T) {
		resp := h.do(request{method: http.MethodOptions, path: "/password/login", header: http.Header{
			"Origin": {"https://evil.test"}, "Access-Control-Request-Method": {"POST"}}})
		require.Empty(t, resp.header.Get("Access-Control-Allow-Origin"))
		require.Empty(t, resp.header.Get("Access-Control-Allow-Credentials"))
	})
}

// TestSecurityAccountEnumeration: unauthenticated recovery and login answers
// must not reveal whether an address has an account.
func TestSecurityAccountEnumeration(t *testing.T) {
	h := newHost(t, withHTTP(generousLimits))
	known := h.newAccount("known")
	unknown := unique("unknown") + "@security.test"
	type shape struct {
		status int
		code   string
	}
	see := func(r response) shape { return shape{r.status, r.errorCode()} }
	t.Run("password login", func(t *testing.T) {
		a := see(h.post("/password/login", map[string]string{"identifier": known.email, "password": "wrong-" + password}, ""))
		b := see(h.post("/password/login", map[string]string{"identifier": unknown, "password": "wrong-" + password}, ""))
		require.Equal(t, a, b)
	})
	t.Run("password reset request", func(t *testing.T) {
		a := h.post("/password/reset/request", map[string]string{"identifier": known.email}, "")
		b := h.post("/password/reset/request", map[string]string{"identifier": unknown}, "")
		require.Equal(t, a.status, b.status)
		require.JSONEq(t, string(orEmpty(a.body)), string(orEmpty(b.body)))
	})
}

func orEmpty(b []byte) []byte {
	if len(bytes.TrimSpace(b)) == 0 {
		return []byte("null")
	}
	return b
}

// TestSecurityVerifyRequestRevealsNothing (owner decision a): an anonymous
// verification request answers a verified, an unverified and an unknown
// address alike, like a password reset request, and sends a code only to the
// unverified one.
func TestSecurityVerifyRequestRevealsNothing(t *testing.T) {
	h := newHost(t, withHTTP(generousLimits))
	verified := h.newAccount("averified").email
	unverified := unique("aunverified") + "@security.test"
	h.register(unverified)
	unknown := unique("aunknown") + "@security.test"
	sent := func(email string) int { return len(h.mail.Messages(iam.MessageVerification, email)) }
	before := map[string]int{verified: sent(verified), unverified: sent(unverified), unknown: sent(unknown)}
	var bodies []string
	for _, email := range []string{verified, unverified, unknown} {
		resp := h.post("/verify/request", map[string]string{"identifier": email}, "")
		require.Equal(t, http.StatusAccepted, resp.status, "%s: %s", email, resp)
		bodies = append(bodies, string(orEmpty(resp.body)))
	}
	require.Equal(t, bodies[0], bodies[1])
	require.Equal(t, bodies[0], bodies[2])
	require.Equal(t, before[verified], sent(verified), "a verified address was mailed a code")
	require.Equal(t, before[unknown], sent(unknown))
	require.Equal(t, before[unverified]+1, sent(unverified), "control: the unverified address gets its code")
}

// TestSecurityVerifyRequestByPhoneRevealsNothing (owner decision a, I8): an
// anonymous verification request answers a verified, an unverified and an
// unknown phone number alike, and texts a code only to the unverified one.
func TestSecurityVerifyRequestByPhoneRevealsNothing(t *testing.T) {
	h := newHost(t, withHTTP(generousLimits), withSMS)
	ctx := context.Background()
	phoneAccount := func(verified bool) string {
		phone := "+1555" + uniqueDigits(7)
		_, err := h.auth.CreateUser(ctx, iam.NewUser{Username: unique("aphone"), Phone: phone, PhoneVerified: verified})
		require.NoError(t, err)
		return phone
	}
	verified, unverified, unknown := phoneAccount(true), phoneAccount(false), "+1555"+uniqueDigits(7)
	sent := func(phone string) int { return len(h.mail.Messages(iam.MessageVerification, phone)) }
	before := map[string]int{verified: sent(verified), unverified: sent(unverified), unknown: sent(unknown)}
	var bodies []string
	for _, phone := range []string{verified, unverified, unknown} {
		resp := h.post("/verify/request", map[string]string{"identifier": phone}, "")
		require.Equal(t, http.StatusAccepted, resp.status, "%s: %s", phone, resp)
		bodies = append(bodies, string(orEmpty(resp.body)))
	}
	require.Equal(t, bodies[0], bodies[1])
	require.Equal(t, bodies[0], bodies[2])
	require.Equal(t, before[verified], sent(verified), "a verified number was texted a code")
	require.Equal(t, before[unknown], sent(unknown))
	require.Equal(t, before[unverified]+1, sent(unverified), "control: the unverified number gets its code")
}

// TestSecurityRegistrationResendRevealsNothing (R5): there is no separate
// registration resend to tell a pending sign-up from an account. The
// anonymous verification request resends a pending registration's code and
// answers a pending, a registered and an unknown address alike.
func TestSecurityRegistrationResendRevealsNothing(t *testing.T) {
	h := newHost(t, withHTTP(generousLimits), authtest.WithConfig(func(c *authkit.Config) {
		c.Registration.Verification = iam.RegistrationVerificationRequired
	}))
	pending := unique("r5pending") + "@security.test"
	resp := h.post("/register", map[string]string{"identifier": pending, "username": unique("r5"), "password": password}, "")
	require.Equal(t, http.StatusAccepted, resp.status, resp.String())
	registered, unknown := h.newAccount("r5registered").email, unique("r5unknown")+"@security.test"
	require.Equal(t, http.StatusNotFound, h.post("/register/resend", map[string]string{"identifier": registered}, "").status)

	sent := func(email string) int { return len(h.mail.Messages(iam.MessageVerification, email)) }
	before := map[string]int{pending: sent(pending), registered: sent(registered), unknown: sent(unknown)}
	var bodies []string
	for _, email := range []string{pending, registered, unknown} {
		resp := h.post("/verify/request", map[string]string{"identifier": email}, "")
		require.Equal(t, http.StatusAccepted, resp.status, "%s: %s", email, resp)
		bodies = append(bodies, string(orEmpty(resp.body)))
	}
	require.Equal(t, bodies[0], bodies[1])
	require.Equal(t, bodies[0], bodies[2])
	require.Equal(t, before[registered], sent(registered))
	require.Equal(t, before[unknown], sent(unknown))
	require.Equal(t, before[pending]+1, sent(pending), "control: the pending registration gets a new code")
	resp = h.post("/verify/confirm", map[string]string{"identifier": pending, "code": h.verificationCode(pending)}, "")
	require.Equal(t, http.StatusOK, resp.status, "the resent code did not complete the registration: %s", resp)
	session(t, resp)
}
