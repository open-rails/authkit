package securitytest

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/open-rails/authkit"
	"github.com/open-rails/authkit/authtest"
	"github.com/open-rails/authkit/iam"
	"github.com/open-rails/authkit/internal/httpapi"
	"github.com/open-rails/authkit/internal/passkeytest"
	"github.com/open-rails/authkit/internal/testdb"
	"github.com/open-rails/authkit/internal/testidp"
	"github.com/stretchr/testify/require"
)

var (
	termsV1   = iam.AgreementRef{Key: "network-terms", Version: "2026-10-10"}
	privacyV1 = iam.AgreementRef{Key: "privacy", Version: "2026-10-10"}
	termsV2   = iam.AgreementRef{Key: "network-terms", Version: "2026-11-01"}
)

// withNetwork is a network host (openrails.dev): passwordless email and SMS
// codes that sign up whoever proves a contact and accepts the network terms
// and privacy policy, passkeys, SMS only to the US and Canada.
func withNetwork(c *authkit.Config) {
	c.Registration.PasswordlessLogin = true
	c.Registration.PasswordlessAutoRegistration = true
	c.Agreements = []authkit.AgreementConfig{
		{Key: termsV1.Key, Version: termsV1.Version, URL: "https://openrails.test/terms"},
		{Key: privacyV1.Key, Version: privacyV1.Version, URL: "https://openrails.test/privacy"},
		{Key: "merchant-terms", Version: "1", URL: "https://openrails.test/merchant-terms"},
	}
	c.Registration.Agreements = []string{termsV1.Key, privacyV1.Key}
	c.SMS.AllowedCountries = []string{"US", "CA"}
	withPasskeys(c)
}

func newNetworkHost(t *testing.T, opts ...authtest.Option) *host {
	t.Helper()
	return newHost(t, append([]authtest.Option{withSMS, httpsFrontend, withHTTP(generousLimits), withHTTP(behindProxy),
		authtest.WithConfig(withNetwork)}, opts...)...)
}

// codeSignIn starts a passwordless sign-in for identifier from address and
// confirms it with the code sent, accepting agreements.
func (h *host) codeSignIn(identifier, address string, agreements ...iam.AgreementRef) response {
	h.t.Helper()
	start := h.do(request{method: http.MethodPost, path: "/passwordless/start", header: from(address),
		body: map[string]string{"identifier": identifier, "mode": "code"}})
	require.Equal(h.t, http.StatusAccepted, start.status, start.String())
	return h.confirmCode(identifier, h.lastCode(identifier), address, agreements...)
}

func (h *host) lastCode(identifier string) string {
	h.t.Helper()
	return h.mail.Last(h.t, iam.MessageVerification, identifier).Code
}

func (h *host) confirmCode(identifier, code, address string, agreements ...iam.AgreementRef) response {
	h.t.Helper()
	body := map[string]any{"identifier": identifier, "code": code}
	if agreements != nil {
		body["agreements"] = agreements
	}
	return h.do(request{method: http.MethodPost, path: "/passwordless/confirm", header: from(address), body: body})
}

// requireAgreementRequired: r refuses for want, named with their URLs.
func requireAgreementRequired(t *testing.T, r response, want ...iam.AgreementRef) {
	t.Helper()
	require.Equal(t, http.StatusConflict, r.status, r.String())
	require.Equal(t, "agreement_required", r.errorCode())
	var env struct {
		Error struct {
			Metadata struct {
				Agreements []iam.Agreement `json:"agreements"`
			} `json:"metadata"`
		} `json:"error"`
	}
	r.json(t, &env)
	var got []iam.AgreementRef
	for _, a := range env.Error.Metadata.Agreements {
		require.True(t, strings.HasPrefix(a.URL, "https://openrails.test/"), a.URL)
		got = append(got, iam.AgreementRef{Key: a.Key, Version: a.Version})
	}
	require.ElementsMatch(t, want, got)
}

func accepted(t *testing.T, h *host, userID string) []iam.AgreementRef {
	t.Helper()
	rows, err := h.auth.UserAgreements(context.Background(), userID)
	require.NoError(t, err)
	var out []iam.AgreementRef
	for _, a := range rows {
		out = append(out, iam.AgreementRef{Key: a.Key, Version: a.Version})
	}
	return out
}

func accessAMR(t *testing.T, token string) []string {
	t.Helper()
	_, claims := splitToken(t, token)
	var out []string
	for _, m := range claims["amr"].([]any) {
		out = append(out, m.(string))
	}
	return out
}

// TestSecurityNetworkAccounts: a network account is a native user who proved
// an email or phone with a code and accepted the network's agreements. A code
// for a new contact signs nobody up until the agreements are accepted, and
// stays valid for that retry; the account records each acceptance; a later
// version marked reaccept is due at the next sign-in. Email and SMS codes
// say which one signed in (amr), and a passkey added after a code sign-in
// signs in on its own.
func TestSecurityNetworkAccounts(t *testing.T) {
	h := newNetworkHost(t)

	t.Run("an emailed code signs up only once the agreements are accepted", func(t *testing.T) {
		email := unique("shopper") + "@security.test"
		start := h.do(request{method: http.MethodPost, path: "/passwordless/start", header: from("203.0.113.1"),
			body: map[string]string{"identifier": email, "mode": "code"}})
		require.Equal(t, http.StatusAccepted, start.status, start.String())
		code := h.lastCode(email)

		requireAgreementRequired(t, h.confirmCode(email, code, "203.0.113.1"), termsV1, privacyV1)
		requireAgreementRequired(t, h.confirmCode(email, code, "203.0.113.1", termsV1), privacyV1)
		requireAgreementRequired(t, h.confirmCode(email, code, "203.0.113.1", iam.AgreementRef{Key: termsV1.Key, Version: "2026-01-01"}, privacyV1), termsV1)
		_, err := h.auth.User(context.Background(), iam.UserByEmail(email))
		require.ErrorIs(t, err, iam.ErrUserNotFound, "no account before the agreements")

		res := authResult(t, h.confirmCode(email, code, "203.0.113.1", termsV1, privacyV1))
		require.Equal(t, httpapi.AuthComplete, res.Status)
		require.True(t, res.Created)
		require.Empty(t, res.AgreementsDue)
		require.True(t, res.User.EmailVerified)
		require.ElementsMatch(t, []iam.AgreementRef{termsV1, privacyV1}, accepted(t, h, res.User.ID))
		rows, err := h.auth.UserAgreements(context.Background(), res.User.ID)
		require.NoError(t, err)
		for _, a := range rows {
			require.Equal(t, iam.AgreementAtRegistration, a.Channel)
			require.WithinDuration(t, time.Now(), a.AcceptedAt, time.Minute)
		}
		require.Equal(t, []string{"email"}, accessAMR(t, res.TokenSet.AccessToken))

		replay := h.confirmCode(email, code, "203.0.113.1", termsV1, privacyV1)
		require.Equal(t, http.StatusUnauthorized, replay.status, "the code was spent: %s", replay)

		again := authResult(t, h.codeSignIn(email, "203.0.113.1"))
		require.Equal(t, httpapi.AuthComplete, again.Status, "an account signs in without accepting again")
		require.False(t, again.Created)
	})

	t.Run("an SMS code signs up and in, its line bound to the frontend's origin", func(t *testing.T) {
		phone := "+14155550111"
		res := authResult(t, h.codeSignIn(phone, "203.0.113.2", termsV1, privacyV1))
		require.Equal(t, httpapi.AuthComplete, res.Status)
		require.True(t, res.Created)
		require.True(t, res.User.PhoneVerified)
		require.Nil(t, res.User.Email)
		msg := h.mail.Last(t, iam.MessageVerification, phone)
		require.Equal(t, "sms", msg.Channel)
		require.Equal(t, "app.security.test", msg.Domain, "the code names the origin it is entered on")
		require.Empty(t, msg.UserID, "a sign-up's code is sent before the account exists")
		require.Equal(t, "@app.security.test #"+msg.Code, iam.SMSMessage{Domain: msg.Domain, Code: msg.Code}.OriginBoundLine())
		require.Equal(t, []string{"sms"}, accessAMR(t, res.TokenSet.AccessToken))

		again := authResult(t, h.codeSignIn(phone, "203.0.113.2"))
		require.Equal(t, httpapi.AuthComplete, again.Status)
		require.Equal(t, res.User.ID, again.User.ID)
		require.Equal(t, res.User.ID, h.mail.Last(t, iam.MessageVerification, phone).UserID)
	})

	t.Run("a passkey added after a code sign-in signs in on its own", func(t *testing.T) {
		email := unique("passkey") + "@security.test"
		res := authResult(t, h.codeSignIn(email, "203.0.113.3", termsV1, privacyV1))
		token := res.TokenSet.AccessToken
		begun := h.post("/me/passkeys/register/begin", nil, token)
		require.Equal(t, http.StatusOK, begun.status, "a code sign-in is fresh enough to add a passkey: %s", begun)
		var creation protocol.CredentialCreation
		begun.json(t, &creation)
		authn := passkeytest.New(t, "http://localhost")
		created := h.do(request{method: http.MethodPost, path: "/me/passkeys/register/finish", token: token, body: json.RawMessage(authn.Register(t, &creation))})
		require.Equal(t, http.StatusCreated, created.status, created.String())

		started := h.post("/passkeys/login/begin", map[string]any{}, "")
		require.Equal(t, http.StatusOK, started.status, started.String())
		var assertion protocol.CredentialAssertion
		started.json(t, &assertion)
		require.Empty(t, assertion.Response.AllowedCredentials, "discoverable: the contact field autofills it")
		signed := authResult(t, h.do(request{method: http.MethodPost, path: "/passkeys/login/finish", body: json.RawMessage(authn.Assert(t, &assertion, 1))}))
		require.Equal(t, httpapi.AuthComplete, signed.Status)
		require.Equal(t, res.User.ID, signed.User.ID)
		require.ElementsMatch(t, []string{"swk", "mfa"}, accessAMR(t, signed.TokenSet.AccessToken))
	})

	t.Run("a password sign-up accepts them too; an account the host made is asked at sign-in", func(t *testing.T) {
		name := unique("pw")
		body := map[string]any{"identifier": name + "@security.test", "username": name, "password": password}
		requireAgreementRequired(t, h.post("/register", body, ""), termsV1, privacyV1)
		body["agreements"] = []iam.AgreementRef{termsV1, privacyV1}
		res := authResult(t, h.post("/register", body, ""))
		require.Equal(t, httpapi.AuthComplete, res.Status)
		require.ElementsMatch(t, []iam.AgreementRef{termsV1, privacyV1}, accepted(t, h, res.User.ID))

		member := h.newAccount("member")
		signed := authResult(t, h.post("/password/login", map[string]string{"identifier": member.email, "password": password}, ""))
		require.ElementsMatch(t, []iam.Agreement{
			{Key: termsV1.Key, Version: termsV1.Version, URL: "https://openrails.test/terms"},
			{Key: privacyV1.Key, Version: privacyV1.Version, URL: "https://openrails.test/privacy"},
		}, signed.AgreementsDue)
		token := signed.TokenSet.AccessToken
		bad := h.post("/me/agreements", map[string]any{"agreements": []iam.AgreementRef{{Key: "unknown", Version: "1"}}}, token)
		require.Equal(t, http.StatusBadRequest, bad.status, bad.String())
		ok := h.post("/me/agreements", map[string]any{"agreements": []iam.AgreementRef{termsV1, privacyV1}}, token)
		require.Equal(t, http.StatusOK, ok.status, ok.String())
		var mine httpapi.UserAgreements
		ok.json(t, &mine)
		require.Empty(t, mine.Due)
		require.Len(t, mine.Accepted, 2)
		require.Equal(t, iam.AgreementInAccount, mine.Accepted[0].Channel)

		require.NoError(t, h.auth.AcceptAgreements(context.Background(), member.id, []iam.AgreementRef{{Key: "merchant-terms", Version: "1"}}))
		require.ErrorIs(t, h.auth.AcceptAgreements(context.Background(), member.id, []iam.AgreementRef{{Key: "merchant-terms", Version: "0"}}), iam.ErrAgreementRequired)
		rows, err := h.auth.UserAgreements(context.Background(), member.id)
		require.NoError(t, err)
		require.Equal(t, iam.AgreementByHost, rows[0].Channel, "merchant-terms sorts first")
	})

	t.Run("a new version marked reaccept is due at the next sign-in", func(t *testing.T) {
		email := unique("reaccept") + "@security.test"
		first := authResult(t, h.codeSignIn(email, "203.0.113.4", termsV1, privacyV1))
		bumped := h.replica(authtest.WithConfig(func(c *authkit.Config) {
			c.Agreements = slices.Clone(c.Agreements)
			c.Agreements[0] = authkit.AgreementConfig{Key: termsV2.Key, Version: termsV2.Version, URL: "https://openrails.test/terms", Reaccept: true}
		}))
		signed := authResult(t, bumped.codeSignIn(email, "203.0.113.4"))
		require.Equal(t, []iam.Agreement{{Key: termsV2.Key, Version: termsV2.Version, URL: "https://openrails.test/terms"}}, signed.AgreementsDue)
		token := signed.TokenSet.AccessToken
		requireAgreementRequired(t, bumped.post("/me/agreements", map[string]any{"agreements": []iam.AgreementRef{termsV1}}, token), termsV2)
		require.Equal(t, http.StatusOK, bumped.post("/me/agreements", map[string]any{"agreements": []iam.AgreementRef{termsV2}}, token).status)
		require.Empty(t, authResult(t, bumped.codeSignIn(email, "203.0.113.4")).AgreementsDue)
		require.ElementsMatch(t, []iam.AgreementRef{termsV1, privacyV1, termsV2}, accepted(t, h, first.User.ID), "acceptances are append-only")
	})
}

// TestSecuritySMSPolicy: text messages go only to SMS.AllowedCountries, by
// the number's real region (a +1 number in Jamaica is not the US), refused
// before anything is looked up or sent; and every message spends the send
// limits per number, account, client address and country, whatever route
// sends it.
func TestSecuritySMSPolicy(t *testing.T) {
	t.Run("only allowed countries", func(t *testing.T) {
		h := newNetworkHost(t)
		for _, number := range []string{"+442079460000", "+18765550123", "+861012345678"} {
			resp := h.do(request{method: http.MethodPost, path: "/passwordless/start", header: from("203.0.113.20"),
				body: map[string]string{"identifier": number, "mode": "code"}})
			require.Equal(t, http.StatusBadRequest, resp.status, "%s: %s", number, resp)
			require.Equal(t, "phone_country_not_allowed", resp.errorCode())
			require.Empty(t, h.mail.Messages("", number))
		}
		for _, number := range []string{"+14155550101", "+14165550101"} {
			resp := h.do(request{method: http.MethodPost, path: "/passwordless/start", header: from("203.0.113.20"),
				body: map[string]string{"identifier": number, "mode": "code"}})
			require.Equal(t, http.StatusAccepted, resp.status, "%s: %s", number, resp)
		}
	})

	t.Run("send limits per number, account, address and country", func(t *testing.T) {
		h := newNetworkHost(t, withHTTP(func(c *authkit.HTTPConfig) {
			c.RateLimits["sms_number"] = authkit.RateLimit{Limit: 2, Window: time.Hour}
			c.RateLimits["sms_account"] = authkit.RateLimit{Limit: 3, Window: time.Hour}
			c.RateLimits["sms_address"] = authkit.RateLimit{Limit: 3, Window: time.Hour}
			c.RateLimits["sms_country"] = authkit.RateLimit{Limit: 8, Window: time.Hour}
		}))
		send := func(number, address string) response {
			return h.do(request{method: http.MethodPost, path: "/passwordless/start", header: from(address),
				body: map[string]string{"identifier": number, "mode": "code"}})
		}
		requireSMSLimited := func(r response, bucket string) {
			t.Helper()
			require.Equal(t, http.StatusTooManyRequests, r.status, r.String())
			require.Equal(t, "rate_limited", r.errorCode())
			require.Equal(t, bucket, r.metadata(t)["action"])
			require.NotEmpty(t, r.header.Get("Retry-After"))
		}

		require.Equal(t, http.StatusAccepted, send("+14155550201", "203.0.113.30").status)
		require.Equal(t, http.StatusAccepted, send("+14155550201", "203.0.113.31").status)
		requireSMSLimited(send("+14155550201", "203.0.113.32"), "sms_number")
		require.Len(t, h.mail.Messages("", "+14155550201"), 2)

		for i, number := range []string{"+14155550202", "+14155550203", "+14155550204"} {
			require.Equal(t, http.StatusAccepted, send(number, "203.0.113.40").status, "send %d", i)
		}
		requireSMSLimited(send("+14155550205", "203.0.113.40"), "sms_address")
		require.Equal(t, http.StatusAccepted, send("+14155550205", "203.0.113.41").status)

		for _, number := range []string{"+14155550206", "+14155550207"} {
			require.Equal(t, http.StatusAccepted, send(number, "203.0.113.50").status)
		}
		requireSMSLimited(send("+14155550208", "203.0.113.51"), "sms_country")
		require.Equal(t, http.StatusAccepted, send("+14165550208", "203.0.113.51").status, "Canada has its own count")
	})

	t.Run("replicas share them through Redis", func(t *testing.T) {
		rdb := testdb.ScratchRedis(t)
		one := newNetworkHost(t, withHTTP(func(c *authkit.HTTPConfig) {
			c.RateLimits["sms_number"] = authkit.RateLimit{Limit: 2, Window: time.Hour}
		}), authtest.WithDeps(func(d *authkit.Deps) { d.Redis = rdb }))
		two := one.replica()
		for i, h := range []*host{one, two, one} {
			resp := h.do(request{method: http.MethodPost, path: "/passwordless/start", header: from("203.0.113.55"),
				body: map[string]string{"identifier": "+14155550250", "mode": "code"}})
			want := http.StatusAccepted
			if i == 2 {
				want = http.StatusTooManyRequests
			}
			require.Equal(t, want, resp.status, "send %d: %s", i, resp)
		}
	})

	t.Run("an account's own codes count against it", func(t *testing.T) {
		h := newNetworkHost(t, withHTTP(func(c *authkit.HTTPConfig) {
			c.RateLimits["sms_account"] = authkit.RateLimit{Limit: 2, Window: time.Hour}
		}))
		phone := "+14155550301"
		res := authResult(t, h.codeSignIn(phone, "203.0.113.60", termsV1, privacyV1))
		for _, address := range []string{"203.0.113.61", "203.0.113.62"} {
			require.Equal(t, http.StatusAccepted, h.do(request{method: http.MethodPost, path: "/passwordless/start", header: from(address),
				body: map[string]string{"identifier": phone, "mode": "code"}}).status, "the sign-up's own code counted against no account")
		}
		resp := h.do(request{method: http.MethodPost, path: "/passwordless/start", header: from("203.0.113.63"),
			body: map[string]string{"identifier": phone, "mode": "code"}})
		require.Equal(t, http.StatusTooManyRequests, resp.status, resp.String())
		require.Equal(t, "sms_account", resp.metadata(t)["action"])
		require.Equal(t, res.User.ID, h.mail.Last(t, iam.MessageVerification, phone).UserID)
	})
}

// TestSecurityPhoneOnlyDevices: an account whose only proof is a phone proves
// it again on every new device, whatever SignIn.NewDevicesPerAccount says (a
// code proves the number, not the person); a device it proved is recognized
// for 30 days, by the partitioned cookie inside an iframe too; a proven email
// or a passkey makes it an ordinary account.
func TestSecurityPhoneOnlyDevices(t *testing.T) {
	for _, limit := range []int{10, -1} {
		h := newNetworkHost(t, authtest.WithConfig(func(c *authkit.Config) { c.SignIn.NewDevicesPerAccount = limit }))
		phone := "+1415555" + map[int]string{10: "0401", -1: "0402"}[limit]
		name := unique("phoneonly")
		u, err := h.auth.CreateUser(context.Background(), iam.NewUser{Phone: phone, PhoneVerified: true, Username: name, Password: password})
		require.NoError(t, err)
		login := func(device *http.Cookie) response {
			return h.do(request{method: http.MethodPost, path: "/password/login", header: from("203.0.113.70"), cookies: []*http.Cookie{device},
				body: map[string]string{"identifier": phone, "password": password}})
		}

		first := newDevice()
		step := deviceStep(t, login(first))
		require.Equal(t, "sms", step.Channel, "limit %d", limit)
		code := h.mail.Last(t, iam.MessageNewDeviceCode, phone)
		require.Equal(t, "app.security.test", code.Domain)
		requireSignedIn(t, h.confirmDevice(step, code.Code, first))
		requireSignedIn(t, login(first), "a device it proved is known")
		deviceStep(t, login(newDevice()))

		// The SMS code is itself the proof: an SMS sign-in on a new device
		// needs nothing more.
		requireSignedIn(t, h.codeSignIn(phone, "203.0.113.71"))

		// Inside a third-party iframe only the partitioned cookie comes back.
		issued := h.do(request{method: http.MethodPost, path: "/password/login", header: from("203.0.113.72"),
			body: map[string]string{"identifier": phone, "password": password}})
		var lax, partitioned *http.Cookie
		for _, c := range issued.cookies {
			switch c.Name {
			case httpapi.CurrentCookie(httpapi.CookieDevice, true).Name:
				lax = c
			case httpapi.CurrentCookie(httpapi.CookieDevicePartitioned, true).Name:
				partitioned = c
			}
		}
		require.NotNil(t, lax)
		require.NotNil(t, partitioned, "an HTTPS deployment also issues the partitioned device cookie")
		require.Equal(t, http.SameSiteNoneMode, partitioned.SameSite)
		require.True(t, partitioned.Secure)
		require.True(t, partitioned.Partitioned)
		require.Equal(t, lax.Value, partitioned.Value)
		frame := &http.Cookie{Name: partitioned.Name, Value: partitioned.Value}
		requireSignedIn(t, h.confirmDevice(deviceStep(t, issued), h.mail.Last(t, iam.MessageNewDeviceCode, phone).Code, frame))
		requireSignedIn(t, login(frame), "the iframe's device is recognized again")

		// A proven email lifts the rule (the account's own limit applies).
		email, verified := name+"@security.test", true
		_, err = h.auth.UpdateUser(context.Background(), iam.SystemIdentity(), u.ID, iam.UserUpdate{Email: &email, EmailVerified: &verified})
		require.NoError(t, err)
		requireSignedIn(t, login(newDevice()), "limit %d", limit)
	}

	t.Run("a passkey lifts it", func(t *testing.T) {
		h := newNetworkHost(t)
		phone := "+14155550403"
		res := authResult(t, h.codeSignIn(phone, "203.0.113.73", termsV1, privacyV1))
		require.NoError(t, h.setPassword(res.User.ID, password))
		login := func() response {
			return h.do(request{method: http.MethodPost, path: "/password/login", header: from("203.0.113.73"), cookies: []*http.Cookie{newDevice()},
				body: map[string]string{"identifier": phone, "password": password}})
		}
		deviceStep(t, login())
		token := authResult(t, h.codeSignIn(phone, "203.0.113.73")).TokenSet.AccessToken
		begun := h.post("/me/passkeys/register/begin", nil, token)
		require.Equal(t, http.StatusOK, begun.status, begun.String())
		var creation protocol.CredentialCreation
		begun.json(t, &creation)
		created := h.do(request{method: http.MethodPost, path: "/me/passkeys/register/finish", token: token,
			body: json.RawMessage(passkeytest.New(t, "http://localhost").Register(t, &creation))})
		require.Equal(t, http.StatusCreated, created.status, created.String())
		requireSignedIn(t, login())
	})
}

// TestSecurityDeletionCheck: Deps.DeletionCheck refuses a user's own deletion
// (deletion_refused with the host's reason) while the host says so, such as
// while the user's cards pay subscriptions, and fails closed when it errs;
// it is never asked about someone else's deletion.
func TestSecurityDeletionCheck(t *testing.T) {
	var mu sync.Mutex
	blocked, failing, asked := map[string]bool{}, map[string]bool{}, []string{}
	h := newNetworkHost(t, authtest.WithDeps(func(d *authkit.Deps) {
		d.DeletionCheck = func(_ context.Context, userID string) error {
			mu.Lock()
			defer mu.Unlock()
			asked = append(asked, userID)
			switch {
			case failing[userID]:
				return errors.New("billing is down")
			case blocked[userID]:
				return iam.RefuseDeletion("subscriptions_active")
			}
			return nil
		}
	}))
	set := func(m map[string]bool, id string, v bool) {
		mu.Lock()
		defer mu.Unlock()
		m[id] = v
	}
	email := unique("deleter") + "@security.test"
	res := authResult(t, h.codeSignIn(email, "203.0.113.80", termsV1, privacyV1))
	token := res.TokenSet.AccessToken

	set(blocked, res.User.ID, true)
	refused := h.do(request{method: http.MethodDelete, path: "/me", token: token})
	require.Equal(t, http.StatusConflict, refused.status, refused.String())
	require.Equal(t, "deletion_refused", refused.errorCode())
	require.Equal(t, "subscriptions_active", refused.metadata(t)["reason"])

	set(blocked, res.User.ID, false)
	set(failing, res.User.ID, true)
	broken := h.do(request{method: http.MethodDelete, path: "/me", token: token})
	require.Equal(t, http.StatusInternalServerError, broken.status, "a failing check refuses: %s", broken)

	set(failing, res.User.ID, false)
	require.Equal(t, http.StatusNoContent, h.do(request{method: http.MethodDelete, path: "/me", token: token}).status)
	u, err := h.auth.User(context.Background(), iam.UserByID(res.User.ID), authkit.IncludeDeleted())
	require.NoError(t, err)
	require.NotNil(t, u.DeletedAt)

	other := h.newAccount("staffdeleted")
	set(blocked, other.id, true)
	out, err := h.auth.DeleteUsers(context.Background(), iam.SystemIdentity(), []string{other.id})
	require.NoError(t, err)
	require.NoError(t, out[0].Err, "the host's own deletion is its decision")
	mu.Lock()
	defer mu.Unlock()
	require.Equal(t, []string{res.User.ID, res.User.ID, res.User.ID}, asked)
	require.False(t, slices.Contains(asked, other.id))
}

// metadata is an error response's metadata.
func (r response) metadata(t *testing.T) map[string]any {
	t.Helper()
	var env iam.ErrorEnvelope
	r.json(t, &env)
	return env.Error.Metadata
}

// TestSecurityAgreementsBeyondCodes: an identity provider's sign-up accepts
// the agreements where its browser flow began, or creates no account; an
// OAuth client that names agreements is approved only for a user who
// accepted them.
func TestSecurityAgreementsBeyondCodes(t *testing.T) {
	t.Run("identity provider sign-up", func(t *testing.T) {
		idp := testidp.New(t)
		h := newNetworkHost(t, withProviders(idp.OIDC("idp")))
		start := func(agreements ...iam.AgreementRef) response {
			body := map[string]any{"return_to": "/welcome"}
			if agreements != nil {
				body["agreements"] = agreements
			}
			return h.do(request{method: http.MethodPost, path: "/oidc/idp/login/start", body: body})
		}
		id := testidp.Identity{Subject: unique("idp"), Email: unique("idp") + "@security.test", EmailVerified: true}
		_, refused := fragmentOf(t, h.oidcCallback(idp, start(), id, "callback", nil))
		require.Equal(t, "agreement_required", refused.Get("error"))
		_, err := h.auth.User(context.Background(), iam.UserByEmail(id.Email))
		require.ErrorIs(t, err, iam.ErrUserNotFound)

		_, fragment := fragmentOf(t, h.oidcCallback(idp, start(termsV1, privacyV1), id, "callback", nil))
		res := authResult(t, h.exchange(fragment.Get("code")))
		require.True(t, res.Created)
		require.ElementsMatch(t, []iam.AgreementRef{termsV1, privacyV1}, accepted(t, h, res.User.ID))
	})

	t.Run("an OAuth client's agreements before approval", func(t *testing.T) {
		as := authtest.NewAuthorizationServer(t, authtest.WithConfig(func(c *authkit.Config) {
			withNetwork(c)
			c.AuthorizationServer.Clients = []authkit.OAuthClientConfig{{
				ID: "merchant-app", RedirectURIs: []string{"https://merchant.test/callback"},
				GrantTypes: []authkit.OAuthGrantType{authkit.GrantAuthorizationCode}, Agreements: []string{termsV1.Key},
			}}
		}))
		u := authtest.NewUser(t, as.Client)
		signedIn := authtest.SignIn(t, as.Client, u)
		flow := authtest.CodeFlow{ClientID: "merchant-app", RedirectURI: "https://merchant.test/callback", Scopes: []string{"openid"}, DPoP: authtest.NewDPoPKey(t)}
		id := as.BeginAuthorization(t, flow, strings.Repeat("v", 43), "state-1")

		view, err := as.HTTPClient().Do(authed(t, http.MethodGet, as.URL+as.Client.APIBase()+"/oauth2/authorizations/"+id, signedIn.AccessToken))
		require.NoError(t, err)
		var pending httpapi.OAuthAuthorizationRequest
		require.NoError(t, json.NewDecoder(view.Body).Decode(&pending))
		view.Body.Close()
		require.Equal(t, []iam.Agreement{{Key: termsV1.Key, Version: termsV1.Version, URL: "https://openrails.test/terms"}}, pending.Agreements)

		approve := func() *http.Response {
			res, err := as.HTTPClient().Do(authed(t, http.MethodPost, as.URL+as.Client.APIBase()+"/oauth2/authorizations/"+id+"/approve", signedIn.AccessToken))
			require.NoError(t, err)
			return res
		}
		refused := approve()
		require.Equal(t, http.StatusConflict, refused.StatusCode)
		var env iam.ErrorEnvelope
		require.NoError(t, json.NewDecoder(refused.Body).Decode(&env))
		refused.Body.Close()
		require.Equal(t, "agreement_required", env.Error.Code)

		require.NoError(t, as.Client.AcceptAgreements(context.Background(), u.ID, []iam.AgreementRef{termsV1}))
		require.Contains(t, as.Approve(t, signedIn.AccessToken, id), "code=", "the same pending request approves once accepted")
	})
}

func authed(t *testing.T, method, target, token string) *http.Request {
	t.Helper()
	r, err := http.NewRequest(method, target, nil)
	require.NoError(t, err)
	r.Header.Set("Authorization", "Bearer "+token)
	return r
}
