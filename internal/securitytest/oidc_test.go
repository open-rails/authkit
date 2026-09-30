package securitytest

import (
	"context"
	"net"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/open-rails/authkit"
	"github.com/open-rails/authkit/authtest"
	"github.com/open-rails/authkit/internal/netguard"
	"github.com/open-rails/authkit/internal/testdb"
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
			Token: authkit.TokenConfig{Issuer: issuer, IssuedAudiences: []string{audience}},
			HTTP:  &authkit.HTTPConfig{DirectPeerIP: true},
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
// so it never rides in a URL (history, logs, Referer). A login start binds it
// to the flow's server-side state from a same-origin POST instead.
func TestSecurityInviteTokenNotInURL(t *testing.T) {
	h := newHost(t, withHTTP(generousLimits), httpsFrontend, withProviders(provider.GitHub("invite-client", "invite-secret")))
	const invite = "invite-secret-token"
	resp := h.get("//oidc/github/login?account_invite_token="+invite, "")
	require.Empty(t, stateCookies(resp), "a GET carrying an invitation started a flow")
	require.False(t, strings.HasPrefix(resp.header.Get("Location"), "https://github.com"), resp.header.Get("Location"))

	start := func(header http.Header) response {
		return h.do(request{method: http.MethodPost, path: "//oidc/github/login", header: header,
			body: map[string]string{"account_invite_token": invite, "return_to": "/welcome"}})
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
