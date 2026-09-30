package securitytest

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"maps"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"slices"
	"strings"
	"sync"
	"testing"

	"github.com/open-rails/authkit"
	"github.com/open-rails/authkit/authtest"
	"github.com/open-rails/authkit/iam"
	"github.com/open-rails/authkit/internal/httpapi"
	"github.com/open-rails/authkit/internal/netguard"
	"github.com/open-rails/authkit/internal/testdb"
	"github.com/open-rails/authkit/internal/testidp"
	"github.com/open-rails/authkit/internal/testkeys"
	"github.com/open-rails/authkit/provider"
	"github.com/stretchr/testify/require"
)

const frontend = "https://app.security.test"

// httpsFrontend serves the deployment's providers from an HTTPS frontend.
var httpsFrontend = authtest.WithConfig(func(c *authkit.Config) { c.Frontend.BaseURL = frontend })

func stateCookies(r response) []*http.Cookie {
	var out []*http.Cookie
	for _, c := range r.cookies {
		if strings.Contains(c.Name, "authkit_oauth_state") {
			out = append(out, c)
		}
	}
	return out
}

// TestSecurityOIDCStateCookieIsHostPrefixed: on HTTPS the flow's state cookie
// is __Host- prefixed (Secure, host-only, Path=/), so a sibling subdomain can
// neither plant nor shadow it.
func TestSecurityOIDCStateCookieIsHostPrefixed(t *testing.T) {
	h := newHost(t, withHTTP(generousLimits), httpsFrontend, withProviders(provider.GitHub("state-client", "state-secret")))
	resp := h.get("//oidc/github/login", "")
	require.Equal(t, http.StatusFound, resp.status, resp.String())
	cookies := stateCookies(resp)
	require.Len(t, cookies, 1)
	require.True(t, strings.HasPrefix(cookies[0].Name, "__Host-"), cookies[0].Name)
	require.True(t, cookies[0].Secure)
	require.Equal(t, "/", cookies[0].Path)
	require.Empty(t, cookies[0].Domain)
}

// TestSecurityProviderIssuerCollisions: provider links are keyed by issuer, so
// two providers may not share one, and none may claim this deployment's own.
func TestSecurityProviderIssuerCollisions(t *testing.T) {
	pg := testdb.ScratchPostgres(t)
	s := signer()
	build := func(providers ...provider.Provider) error {
		runtime, err := authkit.New(context.Background(), authkit.Config{
			Token:     authkit.TokenConfig{Issuer: issuer, IssuedAudiences: []string{audience}},
			TwoFactor: authkit.TwoFactorConfig{Mode: iam.TwoFactorDisabled},
			HTTP:      &authkit.HTTPConfig{DirectPeerIP: true},
		}, authkit.Deps{
			Postgres:  pg.Pool,
			KeySource: testkeys.Source(s),
			Providers: providers,
		})
		if runtime != nil {
			runtime.Close()
		}
		return err
	}
	google := provider.Google("google-client", "google-secret")
	for name, providers := range map[string][]provider.Provider{
		"duplicate issuer":           {google, provider.OIDC("google-alt", "https://accounts.google.com/", "alt-client", "alt-secret")},
		"this deployment's issuer":   {provider.OIDC("self", issuer, "self-client", "self-secret")},
		"deployment issuer spelling": {provider.OIDC("self", strings.ToUpper(issuer)+"/", "self-client", "self-secret")},
	} {
		t.Run(name, func(t *testing.T) {
			require.ErrorContains(t, build(providers...), "issuer")
		})
	}
	t.Run("control: distinct issuers", func(t *testing.T) {
		require.NoError(t, build(google, provider.GitHub("github-client", "github-secret")))
	})
}

// TestSecurityInviteTokenNotInURL: an account invitation is a bearer credential,
// so it never rides in a URL (history, logs, Referer). The JSON login start
// binds it to the flow's server-side state from a same-origin POST instead.
func TestSecurityInviteTokenNotInURL(t *testing.T) {
	h := newHost(t, withHTTP(generousLimits), httpsFrontend, withProviders(provider.GitHub("invite-client", "invite-secret")))
	const invite = "invite-secret-token"
	resp := h.get("//oidc/github/login?invite_code="+invite, "")
	require.Empty(t, stateCookies(resp), "a GET carrying an invitation started a flow")
	require.False(t, strings.HasPrefix(resp.header.Get("Location"), "https://github.com"), resp.header.Get("Location"))

	start := func(header http.Header) response {
		return h.do(request{method: http.MethodPost, path: "/oidc/github/login/start", header: header,
			body: map[string]string{"invite_code": invite, "return_to": "/welcome"}})
	}
	resp = start(nil)
	require.Equal(t, http.StatusOK, resp.status, resp.String())
	var begun struct {
		AuthURL string `json:"auth_url"`
	}
	resp.json(t, &begun)
	require.True(t, strings.HasPrefix(begun.AuthURL, "https://github.com/login/oauth/authorize"), begun.AuthURL)
	require.NotContains(t, begun.AuthURL, invite)
	require.Len(t, stateCookies(resp), 1)

	resp = start(http.Header{"Origin": {"https://evil.test"}, "Sec-Fetch-Site": {"cross-site"}})
	require.Equal(t, http.StatusForbidden, resp.status, resp.String())
	require.Empty(t, stateCookies(resp))
}

// TestSecurityProviderPKCE: every built-in provider whose IdP supports PKCE
// sends an S256 challenge.
func TestSecurityProviderPKCE(t *testing.T) {
	h := newHost(t, withHTTP(generousLimits), httpsFrontend, withProviders(
		provider.GitHub("github-client", "github-secret"),
		provider.Discord("discord-client", "discord-secret")))
	for _, name := range []string{"github", "discord"} {
		t.Run(name, func(t *testing.T) {
			resp := h.get("//oidc/"+name+"/login", "")
			require.Equal(t, http.StatusFound, resp.status, resp.String())
			target, err := url.Parse(resp.header.Get("Location"))
			require.NoError(t, err)
			require.NotEmpty(t, target.Query().Get("code_challenge"), target.String())
			require.Equal(t, "S256", target.Query().Get("code_challenge_method"))
		})
	}
}

// TestSecurityFormPostCallbackIsBounded: the form_post callback is a public,
// cross-site POST; its body is read under a small bound.
func TestSecurityFormPostCallbackIsBounded(t *testing.T) {
	h := newHost(t, withHTTP(generousLimits), httpsFrontend, withProviders(provider.GitHub("form-client", "form-secret")))
	callback := func(body string) response {
		return h.do(request{method: http.MethodPost, path: "//oidc/github/callback?format=json", body: body,
			header: http.Header{"Content-Type": {"application/x-www-form-urlencoded"}}})
	}
	resp := callback("pad=" + strings.Repeat("a", 1<<20) + "&state=forged&code=forged")
	require.Equal(t, http.StatusBadRequest, resp.status, resp.String())
	require.Equal(t, "invalid_request", resp.errorCode(), "an oversized form was parsed")
	t.Run("control: a bounded form is parsed", func(t *testing.T) {
		resp := callback("state=forged&code=forged")
		require.Equal(t, "invalid_state", resp.errorCode(), resp.String())
	})
}

// TestSecurityOutboundAddressGuard: fetches of host-supplied URLs (JWKS)
// never reach reserved ranges, including IPv6
// translation prefixes that embed an arbitrary IPv4 address.
func TestSecurityOutboundAddressGuard(t *testing.T) {
	dial := netguard.DialerWith(net.DefaultResolver, false)
	for _, addr := range []string{"192.0.0.8", "192.0.2.10", "64:ff9b::7f00:1", "64:ff9b::a9fe:a9fe", "64:ff9b:1::a00:1", "2002:7f00:1::1", "2002:a9fe:a9fe::1"} {
		t.Run(addr, func(t *testing.T) {
			require.True(t, netguard.IsPrivateIP(net.ParseIP(addr)))
			conn, err := dial(context.Background(), "tcp", net.JoinHostPort(addr, "443"))
			if conn != nil {
				conn.Close()
			}
			require.ErrorContains(t, err, "private/reserved")
		})
	}
	require.False(t, netguard.IsPrivateIP(net.ParseIP("2001:4860:4860::8888")))
}

// oidcCallback completes a browser's provider flow: the IdP's redirect for id
// (plus extra) to the callback at path, carrying the start's state cookie.
func (h *host) oidcCallback(idp *testidp.IdP, start response, id testidp.Identity, path string, extra url.Values) response {
	h.t.Helper()
	authURL := start.header.Get("Location")
	if start.status == http.StatusOK {
		var begun struct {
			AuthURL string `json:"auth_url"`
		}
		start.json(h.t, &begun)
		authURL = begun.AuthURL
	}
	require.NotEmpty(h.t, authURL, start.String())
	q := idp.Redirect(h.t, authURL, id)
	for k, vs := range extra {
		q[k] = vs
	}
	return h.do(request{method: http.MethodGet, path: "//oidc/idp/" + path + "?" + q.Encode(), cookies: start.cookies})
}

func (h *host) exchange(code string) response {
	h.t.Helper()
	return h.post("/oidc/exchange", map[string]string{"code": code}, "")
}

// fragmentOf is a redirect's URL and its fragment; the URL carries no query
// beyond return_to's own.
func fragmentOf(t *testing.T, r response) (string, url.Values) {
	t.Helper()
	require.Equal(t, http.StatusFound, r.status, r.String())
	location := r.header.Get("Location")
	u, err := url.Parse(location)
	require.NoError(t, err)
	fragment, err := url.ParseQuery(u.Fragment)
	require.NoError(t, err)
	return location, fragment
}

var popupData = regexp.MustCompile(`var data = (\{.*?\});`)

// popupMessage is the message a popup callback posts to its opener.
func popupMessage(t *testing.T, r response) map[string]any {
	t.Helper()
	require.Equal(t, http.StatusOK, r.status, r.String())
	require.Contains(t, r.header.Get("Content-Type"), "text/html")
	m := popupData.FindStringSubmatch(r.String())
	require.Len(t, m, 2, r.String())
	var msg map[string]any
	require.NoError(t, json.Unmarshal([]byte(m[1]), &msg))
	return msg
}

// TestSecurityOIDCResultsCarryNoTokens: a browser OIDC result, a session or a
// continuation, reaches the page only as a one-time code, in the redirect's
// fragment or the popup's message: never an access, refresh or enrollment
// token, whichever transport the mount gives the refresh token. The code
// trades once for the AuthResult; on a cookie mount the callback set the
// refresh cookie and the result carries none.
func TestSecurityOIDCResultsCarryNoTokens(t *testing.T) {
	for _, tc := range []struct {
		name   string
		mode   iam.TwoFactorMode
		status httpapi.AuthStatus
	}{
		{"session", iam.TwoFactorOptional, httpapi.AuthComplete},
		{"enrollment", iam.TwoFactorRequired, httpapi.AuthEnrollmentRequired},
	} {
		for _, cookie := range []bool{false, true} {
			idp := testidp.New(t)
			h := newHost(t, withHTTP(generousLimits), httpsFrontend, withProviders(idp.OIDC("idp")),
				withHTTP(func(c *authkit.HTTPConfig) { c.RefreshCookie = cookie }),
				authtest.WithConfig(func(c *authkit.Config) { c.TwoFactor.Mode = tc.mode }))
			for _, ui := range []string{"redirect", "popup"} {
				t.Run(fmt.Sprintf("%s/refresh_cookie=%t/%s", tc.name, cookie, ui), func(t *testing.T) {
					id := testidp.Identity{Subject: unique("notoken"), Email: unique("notoken") + "@security.test", EmailVerified: true}
					path := "//oidc/idp/login?return_to=/checkout"
					if ui == "popup" {
						path += "&ui=popup&popup_nonce=nonce-1"
					}
					start := h.get(path, "")
					require.Equal(t, http.StatusFound, start.status, start.String())
					callback := h.oidcCallback(idp, start, id, "callback", nil)
					require.Equal(t, "no-store", callback.header.Get("Cache-Control"))
					var carrier, code string
					if ui == "popup" {
						msg := popupMessage(t, callback)
						require.Equal(t, map[string]any{"type": "AUTHKIT_OIDC_RESULT", "nonce": "nonce-1", "provider": "idp", "code": msg["code"]}, msg)
						carrier, code = callback.String(), msg["code"].(string)
					} else {
						var fragment url.Values
						carrier, fragment = fragmentOf(t, callback)
						require.True(t, strings.HasPrefix(carrier, frontend+"/login/callback#"), carrier)
						require.Equal(t, []string{"code", "state"}, slices.Sorted(maps.Keys(fragment)))
						code = fragment.Get("code")
					}
					require.NotEmpty(t, code)
					res := authResult(t, h.exchange(code))
					require.Equal(t, tc.status, res.Status)
					require.Equal(t, "/checkout", *res.ReturnTo)
					var secrets []string
					if res.TokenSet != nil {
						secrets = append(secrets, res.TokenSet.AccessToken)
						if res.TokenSet.RefreshToken != nil {
							secrets = append(secrets, *res.TokenSet.RefreshToken)
						}
					}
					if res.Enrollment != nil {
						secrets = append(secrets, res.Enrollment.TokenSet.AccessToken)
					}
					require.NotEmpty(t, secrets)
					for _, secret := range secrets {
						require.NotContains(t, carrier, secret, "a token rode the browser result")
					}
					for _, key := range []string{"access_token", "refresh_token", "token_set", "enrollment"} {
						require.NotContains(t, carrier, key)
					}
					var refreshCookie *http.Cookie
					for _, c := range callback.cookies {
						if strings.HasSuffix(c.Name, "authkit_rt") && c.MaxAge >= 0 {
							refreshCookie = c
						}
					}
					if tc.status != httpapi.AuthComplete {
						require.Nil(t, refreshCookie, "a continuation holds no session")
						return
					}
					if cookie {
						require.NotNil(t, refreshCookie, "the callback sets the refresh cookie")
						require.Nil(t, res.TokenSet.RefreshToken, "the stored result carries no refresh token on a cookie mount")
					} else {
						require.Nil(t, refreshCookie)
						require.NotNil(t, res.TokenSet.RefreshToken, "a body mount trades the refresh token for the code")
					}
				})
			}
		}
	}
}

// TestSecurityOIDCExchangeCodeIsOneTime: the code a browser result carries is
// stored by its hash, lives two minutes and trades once; a replayed, expired or
// forged code is invalid_state.
func TestSecurityOIDCExchangeCodeIsOneTime(t *testing.T) {
	idp := testidp.New(t)
	h := newHost(t, withHTTP(generousLimits), httpsFrontend, withProviders(idp.OIDC("idp")))
	ctx := context.Background()
	signIn := func() string {
		t.Helper()
		id := testidp.Identity{Subject: unique("once"), Email: unique("once") + "@security.test", EmailVerified: true}
		_, fragment := fragmentOf(t, h.oidcCallback(idp, h.get("//oidc/idp/login", ""), id, "callback", nil))
		require.NotEmpty(t, fragment.Get("code"))
		return fragment.Get("code")
	}
	key := func(code string) string {
		sum := sha256.Sum256([]byte(code))
		return "oidc:result:" + hex.EncodeToString(sum[:])
	}
	invalid := func(resp response) {
		t.Helper()
		require.Equal(t, http.StatusBadRequest, resp.status, resp.String())
		require.Equal(t, "invalid_state", resp.errorCode())
	}

	code := signIn()
	var ttl float64
	require.NoError(t, h.pool.QueryRow(ctx, `SELECT extract(epoch FROM expires_at - now()) FROM profiles.ephemeral_kv WHERE key = $1`, key(code)).Scan(&ttl))
	require.Greater(t, ttl, 0.0)
	require.LessOrEqual(t, ttl, 120.0, "the code lives at most two minutes")
	var raw int
	require.NoError(t, h.pool.QueryRow(ctx, `SELECT count(*) FROM profiles.ephemeral_kv WHERE strpos(key, $1) > 0 OR strpos(encode(value, 'escape'), $1) > 0`, code).Scan(&raw))
	require.Zero(t, raw, "the store holds a usable code")
	require.Equal(t, httpapi.AuthComplete, authResult(t, h.exchange(code)).Status)
	invalid(h.exchange(code))

	t.Run("concurrent trades have one winner", func(t *testing.T) {
		code := signIn()
		var wg sync.WaitGroup
		statuses := make(chan int, 4)
		for range 4 {
			wg.Go(func() { statuses <- h.exchange(code).status })
		}
		wg.Wait()
		close(statuses)
		won := 0
		for status := range statuses {
			if status == http.StatusOK {
				won++
			}
		}
		require.Equal(t, 1, won)
	})
	t.Run("an expired code", func(t *testing.T) {
		code := signIn()
		tag, err := h.pool.Exec(ctx, `UPDATE profiles.ephemeral_kv SET expires_at = now() - interval '1 second' WHERE key = $1`, key(code))
		require.NoError(t, err)
		require.EqualValues(t, 1, tag.RowsAffected())
		invalid(h.exchange(code))
	})
	t.Run("a forged code", func(t *testing.T) {
		invalid(h.exchange("forged-code"))
		resp := h.exchange("")
		require.Equal(t, "invalid_request", resp.errorCode(), resp.String())
	})
}

// TestSecurityOIDCStepUpResultIsACode: a provider step-up returns to the
// page's return_to with a one-time code in the fragment (no token, no query
// flag); the code trades for the session's fresh AuthResult. An identity not
// linked to the session's account fails back to return_to with #error=.
func TestSecurityOIDCStepUpResultIsACode(t *testing.T) {
	idp := testidp.New(t)
	h := newHost(t, withHTTP(generousLimits), httpsFrontend, withProviders(idp.OIDC("idp")))
	a := h.newAccount("oidcstepup")
	id := testidp.Identity{Subject: unique("stepup")}
	token := h.login(a).AccessToken
	link := h.post("/oidc/idp/link/start", map[string]any{}, token)
	require.Equal(t, http.StatusOK, link.status, link.String())
	linked := h.oidcCallback(idp, link, id, "callback", url.Values{"format": {"json"}})
	require.Equal(t, http.StatusNoContent, linked.status, linked.String())

	stale := authtest.StaleSession(t, h.auth, token)
	stepUp := func(who testidp.Identity) response {
		t.Helper()
		start := h.post("/oidc/idp/step-up/start", map[string]string{"return_to": "/settings?tab=security"}, stale)
		require.Equal(t, http.StatusOK, start.status, start.String())
		return h.oidcCallback(idp, start, who, "step-up/callback", nil)
	}

	location, fragment := fragmentOf(t, stepUp(testidp.Identity{Subject: unique("stranger")}))
	require.True(t, strings.HasPrefix(location, "/settings?tab=security#"), location)
	require.Equal(t, "provider_not_linked", fragment.Get("error"))
	require.False(t, fragment.Has("code"))

	location, fragment = fragmentOf(t, stepUp(id))
	require.True(t, strings.HasPrefix(location, "/settings?tab=security#code="), location)
	require.NotContains(t, location, "step_up=")
	res := authResult(t, h.exchange(fragment.Get("code")))
	require.Equal(t, httpapi.AuthComplete, res.Status)
	require.NotNil(t, res.FreshAuth)
	require.False(t, res.FreshAuth.StepUpRequiredForSensitiveActions)
	require.Nil(t, res.TokenSet.RefreshToken, "a step-up never rotates the refresh token")
	require.NotContains(t, location, res.TokenSet.AccessToken)
	require.Equal(t, a.id, res.User.ID)
	_, claims := splitToken(t, res.TokenSet.AccessToken)
	require.Equal(t, a.id, claims["sub"])
}
