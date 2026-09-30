package apitest_test

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/url"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/open-rails/authkit"
	"github.com/open-rails/authkit/authtest"
	"github.com/open-rails/authkit/iam"
	"github.com/open-rails/authkit/internal/testidp"
	"github.com/open-rails/authkit/provider"
)

// providerKinds builds a provider of each kind AuthKit runs: OpenID Connect
// and plain OAuth2.
var providerKinds = map[string]func(*testidp.IdP, string, ...provider.Option) provider.Provider{
	"oidc":   (*testidp.IdP).OIDC,
	"oauth2": (*testidp.IdP).OAuth2,
}

// forEachProviderKind runs fn once per provider kind with a fresh IdP and
// its provider, named "idp".
func forEachProviderKind(t *testing.T, fn func(t *testing.T, idp *testidp.IdP, provider provider.Provider)) {
	for kind, build := range providerKinds {
		t.Run(kind, func(t *testing.T) {
			idp := testidp.New(t)
			fn(t, idp, build(idp, "idp"))
		})
	}
}

// providerLink links id to the account behind token through provider's link
// flow, the callback answered as JSON.
func providerLink(t *testing.T, a *api, idp *testidp.IdP, provider, token string, id testidp.Identity) response {
	t.Helper()
	f := startProviderFlow(t, a.post("/oidc/"+provider+"/link/start", token, map[string]any{}))
	q := idp.Redirect(t, f.authURL, id)
	q.Set("format", "json")
	return f.callback(a, provider, q)
}

// stateCookieName is the name of the __Host- state cookie an HTTPS
// deployment binds state to: httpapi's OIDCStatePrefix plus
// hex(sha256(state)[:4]).
func stateCookieName(state string) string {
	sum := sha256.Sum256([]byte(state))
	return "__Host-authkit_oauth_state_" + hex.EncodeToString(sum[:4])
}

// The callback refuses a forged state, a state started for another provider,
// a tampered nonce, a code bound to another flow's PKCE challenge and a
// replayed state; only the genuine flow completes, on any replica.
func TestOIDCCallbackStateIsBoundAndSingleUse(t *testing.T) {
	idp, other := testidp.New(t), testidp.New(t)
	auth, _ := authtest.New(t, withProviders(idp.OIDC("custom"), other.OIDC("other")))
	id := testidp.Identity{Subject: "state-subject", Email: "oidc-state@example.com", EmailVerified: true}
	start := func(t *testing.T, a *api) providerFlow { return startProviderFlow(t, a.get("//oidc/custom/login", "")) }
	rejected := func(t *testing.T, res response, code string) {
		t.Helper()
		require.Equal(t, http.StatusFound, res.status, res.String())
		location := res.header.Get("Location")
		require.Contains(t, location, "error="+code, location)
		require.NotContains(t, location, "access_token", location)
	}

	t.Run("forged state with a matching forged cookie", func(t *testing.T) {
		a := newAPI(t, auth)
		genuine := start(t, a)
		require.Len(t, genuine.cookies, 1)
		require.Equal(t, stateCookieName(idp.Authorize(t, genuine.authURL).State), genuine.cookies[0].Name,
			"the forged cookie is named as AuthKit names one")
		forged := "forged-state"
		f := providerFlow{cookies: []*http.Cookie{{Name: stateCookieName(forged), Value: forged}}}
		code := idp.Code(id, testidp.Authorization{State: forged})
		rejected(t, f.callback(a, "custom", url.Values{"state": {forged}, "code": {code}}), "invalid_state")
	})

	t.Run("state started for another provider", func(t *testing.T) {
		a := newAPI(t, auth)
		f := start(t, a)
		q := idp.Redirect(t, f.authURL, id)
		rejected(t, f.callback(a, "other", q), "invalid_state")
		// The failed attempt consumed the state: the real provider cannot use it either.
		rejected(t, f.callback(a, "custom", q), "invalid_state")
	})

	t.Run("nonce mismatch", func(t *testing.T) {
		a := newAPI(t, auth)
		f := start(t, a)
		authz := idp.Authorize(t, f.authURL)
		authz.Nonce = "not-" + authz.Nonce
		rejected(t, f.callback(a, "custom", url.Values{"state": {authz.State}, "code": {idp.Code(id, authz)}}), "oidc_exchange_failed")
	})

	t.Run("code bound to another flow's PKCE challenge", func(t *testing.T) {
		a := newAPI(t, auth)
		victim, attacker := start(t, a), start(t, a)
		authz, stolen := idp.Authorize(t, victim.authURL), idp.Authorize(t, attacker.authURL)
		require.NotEmpty(t, authz.CodeChallenge, "login must start a PKCE flow")
		require.NotEqual(t, authz.CodeChallenge, stolen.CodeChallenge)
		// Everything but the challenge matches the victim's flow, so only the
		// victim's verifier can fail the exchange.
		authz.CodeChallenge = stolen.CodeChallenge
		rejected(t, victim.callback(a, "custom", url.Values{"state": {authz.State}, "code": {idp.Code(id, authz)}}), "oidc_exchange_failed")
	})

	t.Run("genuine flow completes once; replay is rejected", func(t *testing.T) {
		a := newAPI(t, auth)
		f := start(t, a)
		q := idp.Redirect(t, f.authURL, id)
		res := f.callback(a, "custom", q)
		fragment := callbackFragment(t, res)
		require.Empty(t, fragment.Get("error"), res.header.Get("Location"))
		require.NotEmpty(t, fragment.Get("access_token"))
		require.NotContains(t, res.header.Get("Location"), "error=")
		// The replay presents the flow's own state cookie, so only the state
		// store can refuse it: the state is gone.
		rejected(t, f.callback(a, "custom", q), "invalid_state")
	})

	t.Run("state issued by one replica completes on another", func(t *testing.T) {
		replica := authtest.Replica(t, auth, withProviders(idp.OIDC("custom"), other.OIDC("other")))
		a := newAPI(t, auth)
		f := start(t, a)
		q := idp.Redirect(t, f.authURL, id)
		res := f.callback(newAPI(t, replica), "custom", q)
		require.Contains(t, res.header.Get("Location"), "access_token", res.header.Get("Location"))
		rejected(t, f.callback(a, "custom", q), "invalid_state")
	})
}

// An unreachable identity provider fails only its own login with 503
// provider_unavailable; genuine client errors keep their statuses, and logins
// recover without a restart once the provider returns.
func TestOIDCProviderOutageIsServiceUnavailable(t *testing.T) {
	idp := testidp.New(t)
	custom := idp.OIDC("custom")
	auth, _ := authtest.New(t, withProviders(custom))
	a := newAPI(t, auth)
	ctx := t.Context()
	id := testidp.Identity{Subject: "outage-subject", Email: "oidc-outage@example.com", EmailVerified: true}
	start := func() response { return a.get("//oidc/custom/login?format=json", "") }
	callback := func(f providerFlow, authz testidp.Authorization) response {
		return f.callback(a, "custom", url.Values{"state": {authz.State}, "code": {idp.Code(id, authz)}, "format": {"json"}})
	}
	unavailable := func(res response) {
		t.Helper()
		require.Equal(t, http.StatusServiceUnavailable, res.status, res.String())
		require.Equal(t, "provider_unavailable", res.code())
	}
	health := custom.(provider.HealthChecker)

	// Discovery unavailable on first use: 503, not 400.
	idp.SetOutage(testidp.Unavailable)
	unavailable(start())
	require.ErrorIs(t, health.CheckHealth(ctx), provider.ErrUnavailable)

	// Recovery is background; the next login after it simply works.
	idp.SetOutage(testidp.Up)
	require.Eventually(t, func() bool { return health.CheckHealth(ctx) == nil }, 10*time.Second, 20*time.Millisecond)
	require.Equal(t, http.StatusFound, start().status)

	// Cached discovery keeps logins starting; a token endpoint outage during
	// the exchange is 503, not 401.
	f := startProviderFlow(t, a.get("//oidc/custom/login", ""))
	idp.SetOutage(testidp.Reset)
	require.Equal(t, http.StatusFound, start().status)
	unavailable(callback(f, idp.Authorize(t, f.authURL)))
	idp.SetOutage(testidp.Unavailable)
	f = startProviderFlow(t, a.get("//oidc/custom/login", ""))
	unavailable(callback(f, idp.Authorize(t, f.authURL)))

	// A genuine rejection from a reachable provider keeps its 401.
	idp.SetOutage(testidp.Up)
	f = startProviderFlow(t, a.get("//oidc/custom/login", ""))
	authz := idp.Authorize(t, f.authURL)
	authz.Nonce = "not-" + authz.Nonce
	res := callback(f, authz)
	require.Equal(t, http.StatusUnauthorized, res.status, res.String())
	require.Equal(t, "oidc_exchange_failed", res.code())

	f = startProviderFlow(t, a.get("//oidc/custom/login", ""))
	require.NotEmpty(t, idp.Authorize(t, f.authURL).CodeChallenge)
	require.NotEmpty(t, callbackFragment(t, f.callback(a, "custom", idp.Redirect(t, f.authURL, id))).Get("access_token"))
}

// A browser sign-in returns to the page it started from only when return_to
// is a path on this site; the redirect's fragment omits anything else.
func TestProviderLoginReturnTo(t *testing.T) {
	idp := testidp.New(t)
	auth, _ := authtest.New(t, withProviders(idp.OAuth2("returns")))
	id := testidp.Identity{Subject: "return-to-subject", Email: "return-to@example.com", EmailVerified: true}
	for _, tt := range []struct {
		name string
		in   string
		want string // "" when the fragment carries no return_to
	}{
		{name: "empty", in: "", want: ""},
		{name: "normal path", in: "/subscribe", want: "/subscribe"},
		{name: "path query", in: "/subscribe?plan=pro&coupon=AK", want: "/subscribe?plan=pro&coupon=AK"},
		{name: "absolute", in: "https://evil.example/subscribe", want: ""},
		{name: "scheme relative", in: "//evil.example/subscribe", want: ""},
		{name: "scheme text", in: "javascript:alert(1)", want: ""},
		{name: "backslash", in: `/\evil`, want: ""},
		{name: "crlf", in: "/ok\r\nLocation:https://evil.example", want: ""},
	} {
		t.Run(tt.name, func(t *testing.T) {
			a := newAPI(t, auth)
			f := startProviderFlow(t, a.get("//oidc/returns/login?"+url.Values{"return_to": {tt.in}}.Encode(), ""))
			fragment := callbackFragment(t, f.callback(a, "returns", idp.Redirect(t, f.authURL, id)))
			require.NotEmpty(t, fragment.Get("access_token"))
			require.Equal(t, tt.want != "", fragment.Has("return_to"))
			require.Equal(t, tt.want, fragment.Get("return_to"))
		})
	}
}

// OIDC and OAuth2 run the same continuation workflow through the real token
// endpoint, browser state cookie, new-account transaction and MFA finish. A
// second-factor challenge is bound to the provider link it started from.
func TestProviderAuthenticationWorkflow(t *testing.T) {
	forEachProviderKind(t, func(t *testing.T, idp *testidp.IdP, provider provider.Provider) {
		auth, outbox := authtest.New(t, withProviders(provider), authtest.WithConfig(func(c *authkit.Config) {
			c.Registration.PasswordlessLogin, c.Registration.PasswordlessAutoRegistration = true, true
			c.TwoFactor.Mode = iam.TwoFactorRequired
		}))
		a := newAPI(t, auth)
		ctx := t.Context()
		id := testidp.Identity{Subject: "provider-flow", Email: "provider-flow@example.com", EmailVerified: true}
		const phone = "+15550100001"

		fragment := providerBrowserSignIn(t, a, idp, "idp", id)
		require.Equal(t, "2fa_enrollment_required", fragment.Get("error"))
		require.Equal(t, "/checkout", fragment.Get("return_to"))
		require.Equal(t, "idp", fragment.Get("provider"))
		grant := fragment.Get("enrollment_token")
		require.NotEmpty(t, grant)
		require.Empty(t, fragment.Get("access_token"))
		require.Empty(t, fragment.Get("refresh_token"))
		require.ElementsMatch(t, []any{"oauth"}, accessClaims(t, grant)["amr"])
		var methods []string
		require.NoError(t, json.Unmarshal([]byte(fragment.Get("allowed_methods")), &methods))
		require.Contains(t, methods, "sms")
		res := a.post("/user/2fa", grant, map[string]any{"method": "sms", "phone_number": phone})
		require.Equal(t, http.StatusAccepted, res.status, res.String())
		enrolled := expectAnswer(t, a.post("/user/2fa", grant, map[string]any{"method": "sms", "phone_number": phone,
			"code": outbox.Last(t, authtest.Verification, phone).Code}), http.StatusOK)
		owner := requireSessionWith(t, a, auth, enrolled.tokens(), "oauth", "sms", "otp", "mfa").UserID

		next := expectAnswer(t, providerSignIn(t, a, idp, "idp", id, ""), http.StatusForbidden)
		require.Equal(t, "2fa_required", next.Error.Code)
		require.Equal(t, "sms", next.Error.Metadata.Method)
		require.Equal(t, owner, next.Error.Metadata.UserID, "a known provider identity never creates a second account or re-enrolls")
		verify2FA := func(challenge authAnswer, code string) response {
			return a.post("/2fa/verify", "", map[string]any{"user_id": owner, "challenge": challenge.Error.Metadata.Challenge, "code": code})
		}
		finished := expectAnswer(t, verify2FA(next, outbox.Last(t, authtest.LoginCode, phone).Code), http.StatusOK)
		requireSessionWith(t, a, auth, finished.tokens(), "oauth", "sms", "otp", "mfa")
		require.Equal(t, "idp", accessClaims(t, finished.tokens().AccessToken)["provider"])

		// Deleting and recreating the same issuer and subject cannot revive a
		// challenge that belonged to the previous provider-link row. A
		// password keeps the unlink from removing the last login method.
		backup := "Provider-backup-password-123"
		_, err := auth.UpdateUser(ctx, iam.SystemActor(), owner, iam.UserUpdate{Password: &backup})
		require.NoError(t, err)
		fresh := expectAnswer(t, providerSignIn(t, a, idp, "idp", id, ""), http.StatusForbidden)
		session := expectAnswer(t, verify2FA(fresh, outbox.Last(t, authtest.LoginCode, phone).Code), http.StatusOK).tokens()
		stale := expectAnswer(t, providerSignIn(t, a, idp, "idp", id, ""), http.StatusForbidden)
		code := outbox.Last(t, authtest.LoginCode, phone).Code
		res = a.do(request{method: http.MethodDelete, path: "/user/providers/idp", token: session.AccessToken})
		require.Equal(t, http.StatusNoContent, res.status, res.String())
		require.NoError(t, auth.LinkProvider(ctx, owner, iam.ProviderLink{Issuer: provider.Issuer(), Provider: "idp", Subject: id.Subject}))
		res = verify2FA(stale, code)
		require.Equal(t, http.StatusUnauthorized, res.status, res.String())
	})
}

// Linking needs a recent sign-in, and a linked provider is replaced only by
// an explicit unlink.
func TestProviderLinkRequiresFreshAuthAndExplicitUnlink(t *testing.T) {
	forEachProviderKind(t, func(t *testing.T, idp *testidp.IdP, provider provider.Provider) {
		auth, _ := authtest.New(t, withProviders(provider), authtest.WithConfig(func(c *authkit.Config) { c.SolanaNetwork = iam.SolanaDevnet }))
		a := newAPI(t, auth)
		u := authtest.NewUser(t, auth)
		stale := authtest.StaleSession(t, auth, authtest.SignIn(t, auth, u).AccessToken)
		denied := a.post("/oidc/idp/link/start", stale, map[string]any{})
		require.Equal(t, http.StatusForbidden, denied.status, denied.String())
		require.Equal(t, "step_up_required", denied.code())
		require.Empty(t, denied.cookies)
		denied = a.post("/solana/link", stale, map[string]any{})
		require.Equal(t, http.StatusForbidden, denied.status, denied.String())
		require.Equal(t, "step_up_required", denied.code())
		fresh := expectAnswer(t, a.post("/step-up/password", stale, map[string]string{"password": u.Password}), http.StatusOK).tokens().AccessToken
		require.NotEmpty(t, fresh)

		original := testidp.Identity{Subject: "original"}
		res := providerLink(t, a, idp, "idp", fresh, original)
		require.Equal(t, http.StatusNoContent, res.status, res.String())
		res = providerLink(t, a, idp, "idp", fresh, testidp.Identity{Subject: "replacement"})
		require.Equal(t, http.StatusConflict, res.status, res.String())
		require.Equal(t, "provider_change_requires_unlink", res.code())
		signedIn := expectAnswer(t, providerSignIn(t, a, idp, "idp", original, ""), http.StatusOK)
		require.Equal(t, u.ID, signedIn.User.ID, "the original identity still signs in to the account")
		res = a.do(request{method: http.MethodDelete, path: "/user/providers/idp", token: fresh})
		require.Equal(t, http.StatusNoContent, res.status, res.String())
		res = providerLink(t, a, idp, "idp", fresh, testidp.Identity{Subject: "replacement"})
		require.Equal(t, http.StatusNoContent, res.status, res.String())
	})
}

// A trusted provider that does not assert the email it reports (the claim is
// absent) never reserves the address: the account it creates has no email and
// no reset reaches it, and the address's proven owner gets its own account.
func TestFederatedUnverifiedEmailDoesNotReserveAccountAddress(t *testing.T) {
	forEachProviderKind(t, func(t *testing.T, idp *testidp.IdP, provider provider.Provider) {
		auth, outbox := authtest.New(t, withProviders(provider))
		a := newAPI(t, auth)
		ctx := t.Context()
		const email = "unverified-provider@example.com"
		attacker := testidp.Identity{Subject: "attacker", Email: email}
		first := expectAnswer(t, providerSignIn(t, a, idp, "idp", attacker, ""), http.StatusOK)
		require.Nil(t, first.User.Email)
		u, err := auth.User(ctx, iam.UserByID(first.User.ID))
		require.NoError(t, err)
		require.Empty(t, u.Email)
		again := expectAnswer(t, providerSignIn(t, a, idp, "idp", attacker, ""), http.StatusOK)
		require.Equal(t, first.User.ID, again.User.ID, "the link belongs to the account it created")
		res := a.post("/password/reset/request", "", map[string]string{"identifier": email})
		require.Equal(t, http.StatusAccepted, res.status, res.String())
		require.Empty(t, outbox.Messages(authtest.PasswordReset, email))

		second := expectAnswer(t, providerSignIn(t, a, idp, "idp", testidp.Identity{Subject: "owner", Email: email, EmailVerified: true}, ""), http.StatusOK)
		require.NotEqual(t, first.User.ID, second.User.ID)
		require.NotNil(t, second.User.Email)
		require.Equal(t, email, *second.User.Email)
		u, err = auth.User(ctx, iam.UserByID(second.User.ID))
		require.NoError(t, err)
		require.True(t, u.EmailVerified)
	})
}

// On an invite-only deployment a provider sign-in without a proven email
// registers only with an invitation, which it consumes.
func TestFederatedEmailLessRegistrationRequiresAndConsumesInvite(t *testing.T) {
	forEachProviderKind(t, func(t *testing.T, idp *testidp.IdP, provider provider.Provider) {
		auth, _ := authtest.New(t, withProviders(provider), authtest.WithConfig(func(c *authkit.Config) {
			c.Registration.NativeUserMode = iam.RegistrationModeInviteOnly
		}))
		a := newAPI(t, auth)
		id := testidp.Identity{Subject: "invite-user", Email: "unverified-invite@example.com"}
		res := providerSignIn(t, a, idp, "idp", id, "")
		require.Equal(t, http.StatusForbidden, res.status, res.String())
		invite, err := auth.CreateInvitation(t.Context(), iam.SystemActor(), iam.RootGroup(), iam.NewInvitation{Email: "invite-destination@example.com"})
		require.NoError(t, err)
		allowed := expectAnswer(t, providerSignIn(t, a, idp, "idp", id, invite.Code), http.StatusOK)
		require.NotEmpty(t, allowed.User.ID)
		require.Nil(t, allowed.User.Email)
		// A second use finds no invitation: the first consumed it.
		res = providerSignIn(t, a, idp, "idp", testidp.Identity{Subject: "another", Email: id.Email}, invite.Code)
		require.Equal(t, http.StatusNotFound, res.status, res.String())
	})
}

// A link started by a session that is revoked before the IdP answers never
// adds the provider.
func TestCredentialTransactionsProviderLinkGrantDoesNotOutliveSessionRevocation(t *testing.T) {
	forEachProviderKind(t, func(t *testing.T, idp *testidp.IdP, provider provider.Provider) {
		auth, _ := authtest.New(t, withProviders(provider))
		a := newAPI(t, auth)
		u := authtest.NewUser(t, auth)
		f := startProviderFlow(t, a.post("/oidc/idp/link/start", authtest.SignIn(t, auth, u).AccessToken, map[string]any{}))
		_, err := auth.RevokeAccountSessions(t.Context(), iam.SystemActor(), u.ID)
		require.NoError(t, err)
		id := testidp.Identity{Subject: "revoked-link"}
		q := idp.Redirect(t, f.authURL, id)
		q.Set("format", "json")
		res := f.callback(a, "idp", q)
		require.NotEqual(t, http.StatusNoContent, res.status, "a revoked session linked a provider: %s", res)
		other := expectAnswer(t, providerSignIn(t, a, idp, "idp", id, ""), http.StatusOK)
		require.NotEqual(t, u.ID, other.User.ID, "the identity was linked to the revoked session's account")
	})
}

// A browser link keeps the session that started it and hands the page no
// tokens; the callback only clears the consumed state cookie.
func TestCredentialTransactionsProviderLinkBrowserRetainsSession(t *testing.T) {
	forEachProviderKind(t, func(t *testing.T, idp *testidp.IdP, provider provider.Provider) {
		auth, _ := authtest.New(t, withProviders(provider))
		a := newAPI(t, auth)
		u := authtest.NewUser(t, auth)
		token := authtest.SignIn(t, auth, u).AccessToken
		claims, err := auth.Verify(t.Context(), token)
		require.NoError(t, err)
		f := startProviderFlow(t, a.post("/oidc/idp/link/start", token, map[string]any{}))
		res := f.callback(a, "idp", idp.Redirect(t, f.authURL, testidp.Identity{Subject: "browser-link"}))
		fragment := callbackFragment(t, res)
		require.Equal(t, "link", fragment.Get("flow"))
		require.Equal(t, "success", fragment.Get("result"))
		require.Empty(t, fragment.Get("access_token"))
		require.Empty(t, fragment.Get("refresh_token"))
		for _, cookie := range res.cookies {
			require.Negative(t, cookie.MaxAge, "callback may only clear consumed state cookies")
		}
		sessions, err := auth.Sessions(t.Context(), u.ID)
		require.NoError(t, err)
		require.Len(t, sessions, 1)
		require.Equal(t, claims.SessionID, sessions[0].ID)
	})
}
