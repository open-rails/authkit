package securitytest

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/open-rails/authkit"
	"github.com/open-rails/authkit/authtest"
	"github.com/open-rails/authkit/iam"
	"github.com/open-rails/authkit/internal/ident"
	"github.com/open-rails/authkit/internal/jose"
	"github.com/open-rails/authkit/keys"
	hauth "github.com/open-rails/helpers/auth"
	"github.com/stretchr/testify/require"
)

const merchantAPI = "https://api.network.test"

// network is an openrails.dev-like deployment: merchants' groups register
// OAuth clients ("Sign in with openrails.dev"), which ask for OpenID's
// scopes and the network's own, and are approved only by users who accepted
// the network terms.
type network struct {
	*authtest.AuthorizationServer
	t        *testing.T
	merchant iam.Persona
	mu       sync.Mutex
	events   []iam.Event
	// consentCheck is Deps.ConsentRevocationCheck; nil allows.
	consentCheck func(ctx context.Context, userID, clientID string) error
}

// newNetwork serves the deployment as a host does, its routes mounted in the
// host's own handler on its own server, and attaches authtest to it.
func newNetwork(t *testing.T) *network {
	t.Helper()
	n := &network{t: t}
	var handler atomic.Pointer[http.Handler]
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if h := handler.Load(); h != nil {
			(*h).ServeHTTP(w, r)
			return
		}
		http.Error(w, "starting", http.StatusServiceUnavailable)
	}))
	t.Cleanup(server.Close)
	auth, _ := authtest.New(t, authtest.WithConfig(func(c *authkit.Config) {
		c.Token.Issuer, c.Token.AllowPrivateNetworkJWKS = server.URL, true
		withNetwork(c)
		r := authkit.NewRoles()
		merchant := r.Persona("merchant", authkit.OAuthClients)
		merchant.Role("staff", merchant.Credentials.All())
		c.Roles = r
		c.AuthorizationServer.Resources = []authkit.ResourceServerConfig{{ID: merchantAPI, Scopes: []string{"openrails:self", "openrails:link"}}}
		c.AuthorizationServer.GroupClients = authkit.GroupClientsConfig{
			Scopes: []authkit.GroupClientScope{
				{Name: "openrails:self", Resource: merchantAPI, Description: "See and manage your subscriptions here"},
				{Name: "openrails:link", Resource: merchantAPI, Description: "Link your account here to your network account"},
			},
			Agreements: []string{termsV1.Key},
		}
		c.Resource = authkit.ResourceConfig{ID: merchantAPI}
	}), authtest.WithDeps(func(d *authkit.Deps) {
		d.GroupName = func(_ context.Context, groupID string) (string, error) { return "Merchant " + groupID[:8], nil }
		d.OnEvent = func(_ context.Context, e iam.Event) error {
			n.mu.Lock()
			defer n.mu.Unlock()
			n.events = append(n.events, e)
			return nil
		}
		d.ConsentRevocationCheck = func(ctx context.Context, userID, clientID string) error {
			n.mu.Lock()
			check := n.consentCheck
			n.mu.Unlock()
			if check == nil {
				return nil
			}
			return check(ctx, userID, clientID)
		}
	}))
	mux := http.NewServeMux()
	mux.Handle("/", auth.Handler())
	var h http.Handler = mux
	handler.Store(&h)
	n.AuthorizationServer = authtest.Attach(t, auth, server)
	n.merchant = ident.Persona("merchant")
	require.NoError(t, n.Client.Start(context.Background()), "River delivers events and back-channel logouts")
	return n
}

// group creates a merchant group owned by a staff user, and the staff's
// sign-in.
func (n *network) group() (iam.GroupRef, authtest.User, iam.TokenSet) {
	n.t.Helper()
	staff := authtest.NewUser(n.t, n.Client)
	owner := iam.UserSubject(staff.ID)
	g, err := n.Client.CreateGroup(context.Background(), iam.NewGroup{Persona: n.merchant, Owner: &owner})
	require.NoError(n.t, err)
	return iam.GroupByID(g.ID), staff, authtest.SignIn(n.t, n.Client, staff)
}

// api calls the JSON API with a token.
func (n *network) api(method, path, token string, body any) (int, []byte) {
	n.t.Helper()
	var r io.Reader
	if body != nil {
		raw, err := json.Marshal(body)
		require.NoError(n.t, err)
		r = strings.NewReader(string(raw))
	}
	req, err := http.NewRequest(method, n.URL+n.Client.APIBase()+path, r)
	require.NoError(n.t, err)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	res, err := n.HTTPClient().Do(req)
	require.NoError(n.t, err)
	defer res.Body.Close()
	out, _ := io.ReadAll(res.Body)
	return res.StatusCode, out
}

func errorCode(t *testing.T, body []byte) string {
	t.Helper()
	var env iam.ErrorEnvelope
	require.NoError(t, json.Unmarshal(body, &env), string(body))
	return env.Error.Code
}

// authorize begins a code flow and approves it as signedIn, with consent
// when asked; it returns the approval's status and body.
func (n *network) authorize(flow authtest.CodeFlow, signedIn iam.TokenSet, consent bool) (string, int, []byte) {
	n.t.Helper()
	verifier := strings.Repeat("v", 43) + randomSuffix()
	id := n.BeginAuthorization(n.t, flow, verifier, "state-"+randomSuffix())
	var body any
	if consent {
		body = map[string]bool{"consent": true}
	}
	status, out := n.api(http.MethodPost, "/oauth2/authorizations/"+id+"/approve", signedIn.AccessToken, body)
	return verifier, status, out
}

func randomSuffix() string { return strings.ToLower(unique("x")) }

// redeem trades the approval's code for tokens as the client.
func (n *network) redeem(flow authtest.CodeFlow, verifier string, approval []byte, extra url.Values) (int, authtest.OAuthTokens, []byte) {
	n.t.Helper()
	var res struct {
		RedirectTo string `json:"redirect_to"`
	}
	require.NoError(n.t, json.Unmarshal(approval, &res), string(approval))
	u, err := url.Parse(res.RedirectTo)
	require.NoError(n.t, err)
	require.Equal(n.t, n.URL, u.Query().Get("iss"), "RFC 9207 iss")
	params := url.Values{"grant_type": {"authorization_code"}, "code": {u.Query().Get("code")}, "redirect_uri": {flow.RedirectURI}, "code_verifier": {verifier}}
	for k, vs := range extra {
		params[k] = vs
	}
	status, body := n.Token(n.t, authtest.TokenRequest{ClientID: flow.ClientID, ClientSecret: flow.ClientSecret, Params: params})
	var tokens authtest.OAuthTokens
	if status == http.StatusOK {
		require.NoError(n.t, json.Unmarshal(body, &tokens))
	}
	return status, tokens, body
}

func jwtClaims(t *testing.T, token string) map[string]any {
	t.Helper()
	_, claims, ok := jose.Unverified(token)
	require.True(t, ok)
	return claims
}

// TestSecurityGroupOAuthClients: a merchant's group registers its own OAuth
// client at run time and signs network users in with the code flow and
// PKCE. Each user consents per scope, once, additively; the merchant gets
// only proven contact claims and the user's public network id (sub); its
// tokens act only in its group; withdrawn consent, a disabled client and a
// deleted group end them.
func TestSecurityGroupOAuthClients(t *testing.T) {
	n := newNetwork(t)
	ctx := context.Background()
	groupA, staffA, staffSession := n.group()
	groupB, _, _ := n.group()

	// The merchant's back-channel logout endpoint.
	logouts := make(chan string, 4)
	bcl := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.NoError(t, r.ParseForm())
		logouts <- r.PostForm.Get("logout_token")
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(bcl.Close)

	// Registered over HTTP by the merchant's staff (credentials:manage).
	status, body := n.api(http.MethodPost, "/groups/"+groupA.ID()+"/oauth-clients", staffSession.AccessToken, iam.NewOAuthClient{
		ClientName: "Shop A", RedirectURIs: []string{"https://shop-a.test/callback"}, TokenEndpointAuthMethod: iam.OAuthClientSecretBasic,
		Scope: "openid email phone profile openrails:self", LogoURI: "https://shop-a.test/logo.png", BackchannelLogoutURI: bcl.URL + "/logout",
	})
	require.Equal(t, http.StatusCreated, status, string(body))
	var created iam.OAuthClientCreated
	require.NoError(t, json.Unmarshal(body, &created))
	require.True(t, strings.HasPrefix(created.ClientID, "goc_"))
	require.NotNil(t, created.ClientSecret)
	flow := authtest.CodeFlow{ClientID: created.ClientID, ClientSecret: *created.ClientSecret, RedirectURI: "https://shop-a.test/callback",
		Scopes: []string{"openid", "email", "phone", "openrails:self"}}

	t.Run("registration rules", func(t *testing.T) {
		stranger := authtest.SignIn(t, n.Client, authtest.NewUser(t, n.Client))
		s, b := n.api(http.MethodPost, "/groups/"+groupA.ID()+"/oauth-clients", stranger.AccessToken, iam.NewOAuthClient{ClientName: "X",
			RedirectURIs: []string{"https://x.test/cb"}, TokenEndpointAuthMethod: iam.OAuthClientNone, Scope: "openid"})
		require.Equal(t, http.StatusForbidden, s, string(b))
		for _, bad := range []iam.NewOAuthClient{
			{ClientName: "X", RedirectURIs: []string{"http://x.test/cb"}, TokenEndpointAuthMethod: iam.OAuthClientNone, Scope: "openid"},
			{ClientName: "X", RedirectURIs: []string{"https://x.test/cb#f"}, TokenEndpointAuthMethod: iam.OAuthClientNone, Scope: "openid"},
			{ClientName: "X", RedirectURIs: []string{"https://x.test/cb"}, TokenEndpointAuthMethod: iam.OAuthClientNone, Scope: "email"},
			{ClientName: "X", RedirectURIs: []string{"https://x.test/cb"}, TokenEndpointAuthMethod: iam.OAuthClientNone, Scope: "openid admin:all"},
			{ClientName: "X", RedirectURIs: []string{"https://x.test/cb"}, TokenEndpointAuthMethod: iam.OAuthClientPrivateKeyJWT, Scope: "openid"},
		} {
			s, b := n.api(http.MethodPost, "/groups/"+groupA.ID()+"/oauth-clients", staffSession.AccessToken, bad)
			require.Equal(t, http.StatusBadRequest, s, string(b))
			require.Equal(t, "invalid_oauth_client", errorCode(t, b))
		}
		listed, err := n.Client.GroupOAuthClients(ctx, groupA)
		require.NoError(t, err)
		require.Len(t, listed, 1)
		require.Equal(t, "Shop A", listed[0].ClientName)
		for range iam.MaxGroupOAuthClients - 1 {
			_, err := n.Client.CreateGroupOAuthClient(ctx, iam.SystemIdentity(), groupA, iam.NewOAuthClient{ClientName: "Filler",
				RedirectURIs: []string{"https://fill.test/cb"}, TokenEndpointAuthMethod: iam.OAuthClientNone, Scope: "openid"})
			require.NoError(t, err)
		}
		_, err = n.Client.CreateGroupOAuthClient(ctx, iam.SystemIdentity(), groupA, iam.NewOAuthClient{ClientName: "One too many",
			RedirectURIs: []string{"https://fill.test/cb"}, TokenEndpointAuthMethod: iam.OAuthClientNone, Scope: "openid"})
		require.ErrorIs(t, err, iam.ErrOAuthClientLimitReached)
		for _, c := range must(n.Client.GroupOAuthClients(ctx, groupA)) {
			if c.ClientName == "Filler" {
				require.NoError(t, n.Client.DeleteGroupOAuthClient(ctx, iam.SystemIdentity(), groupA, c.ClientID))
			}
		}
	})

	shopper := authtest.NewUser(t, n.Client)
	phone := "+14155550901"
	_, err := n.Client.UpdateUser(ctx, iam.SystemIdentity(), shopper.ID, iam.UserUpdate{Phone: &phone, PhoneVerified: ptr(false)})
	require.NoError(t, err)
	signedIn := authtest.SignIn(t, n.Client, shopper)

	t.Run("code with PKCE, the network terms, then consent per scope", func(t *testing.T) {
		_, s, b := n.authorize(flow, signedIn, true)
		require.Equal(t, http.StatusConflict, s, string(b))
		require.Equal(t, "agreement_required", errorCode(t, b))
		require.NoError(t, n.Client.AcceptAgreements(ctx, shopper.ID, []iam.AgreementRef{termsV1}))

		_, s, b = n.authorize(flow, signedIn, false)
		require.Equal(t, http.StatusConflict, s, string(b))
		require.Equal(t, "consent_required", errorCode(t, b))
		var env struct {
			Error struct {
				Metadata struct {
					Scopes []struct{ Name, Description string } `json:"scopes"`
				} `json:"metadata"`
			} `json:"error"`
		}
		require.NoError(t, json.Unmarshal(b, &env))
		require.Len(t, env.Error.Metadata.Scopes, 4)
		require.Equal(t, "See and manage your subscriptions here", env.Error.Metadata.Scopes[3].Description)

		verifier, s, b := n.authorize(flow, signedIn, true)
		require.Equal(t, http.StatusOK, s, string(b))
		status, tokens, raw := n.redeem(flow, verifier, b, nil)
		require.Equal(t, http.StatusOK, status, string(raw))
		at := jwtClaims(t, tokens.AccessToken)
		require.Equal(t, shopper.ID, at["sub"], "the public network id is sub")
		require.Equal(t, merchantAPI, at["aud"])
		require.Equal(t, created.ClientID, at["client_id"])
		require.Empty(t, at["permissions"], "a merchant's token carries none of the deployment's grants")
		require.Empty(t, at["roles"])
		require.Equal(t, shopper.Email, at["email"])
		require.NotContains(t, at, "phone_number", "an unproven phone is never released")
		id := jwtClaims(t, tokens.IDToken)
		require.Equal(t, []any{created.ClientID}, id["aud"])
		require.Equal(t, true, id["email_verified"])
		require.NotContains(t, id, "phone_number")
		require.NotContains(t, id, "roles")
		require.NotContains(t, id, "preferred_username")

		// The same scopes again: remembered, no screen.
		verifier, s, b = n.authorize(flow, signedIn, false)
		require.Equal(t, http.StatusOK, s, string(b))
		status, _, raw = n.redeem(flow, verifier, b, nil)
		require.Equal(t, http.StatusOK, status, string(raw))

		// A new scope asks for that one only; prompt=consent asks for all.
		more := flow
		more.Scopes = append(append([]string(nil), flow.Scopes...), "profile")
		_, s, b = n.authorize(more, signedIn, false)
		require.Equal(t, http.StatusConflict, s)
		require.NoError(t, json.Unmarshal(b, &env))
		require.Len(t, env.Error.Metadata.Scopes, 1)
		require.Equal(t, "profile", env.Error.Metadata.Scopes[0].Name)
		again := flow
		again.Prompt = "consent"
		_, s, b = n.authorize(again, signedIn, false)
		require.Equal(t, http.StatusConflict, s, string(b))
		require.NoError(t, json.Unmarshal(b, &env))
		require.Len(t, env.Error.Metadata.Scopes, 4)
	})

	t.Run("tokens act only in the client's group", func(t *testing.T) {
		verifier, s, b := n.authorize(flow, signedIn, false)
		status, tokens, raw := n.redeem(flow, verifier, b, nil)
		require.Equal(t, http.StatusOK, status, string(raw))
		req := httptest.NewRequest(http.MethodGet, merchantAPI+"/v1/me", nil)
		req.Header.Set("Authorization", "Bearer "+tokens.AccessToken)
		v, err := n.Client.Authenticator().Authenticate(req)
		require.NoError(t, err)
		bound, ok := v.(hauth.Bound)
		require.True(t, ok)
		scopeA, err := n.Client.Scope(ctx, groupA)
		require.NoError(t, err)
		scopeB, err := n.Client.Scope(ctx, groupB)
		require.NoError(t, err)
		require.Equal(t, scopeA, bound.BoundScope())
		checker, ok := v.(hauth.PermissionChecker)
		require.True(t, ok)
		allowed, err := checker.Can(ctx, scopeB, "merchant:credentials:read")
		require.NoError(t, err)
		require.False(t, allowed, "never in another merchant's group")

		// Even the merchant's own staff signing in through its client gets
		// none of their staff authority there.
		staffFlow := flow
		staffSignIn := authtest.SignIn(t, n.Client, staffA)
		require.NoError(t, n.Client.AcceptAgreements(ctx, staffA.ID, []iam.AgreementRef{termsV1}))
		verifier, s, b = n.authorize(staffFlow, staffSignIn, true)
		require.Equal(t, http.StatusOK, s, string(b))
		status, staffTokens, raw := n.redeem(staffFlow, verifier, b, nil)
		require.Equal(t, http.StatusOK, status, string(raw))
		req = httptest.NewRequest(http.MethodGet, merchantAPI+"/v1/me", nil)
		req.Header.Set("Authorization", "Bearer "+staffTokens.AccessToken)
		sv, err := n.Client.Authenticator().Authenticate(req)
		require.NoError(t, err)
		allowed, err = sv.(hauth.PermissionChecker).Can(ctx, scopeA, "merchant:credentials:read")
		require.NoError(t, err)
		require.False(t, allowed, "a group client's token holds only what its scopes grant")
		require.Equal(t, shopper.ID, v.Identity().Subject)
	})

	t.Run("withdrawn consent ends refresh, logs the merchant out, records the event", func(t *testing.T) {
		verifier, _, b := n.authorize(flow, signedIn, false)
		status, tokens, raw := n.redeem(flow, verifier, b, nil)
		require.Equal(t, http.StatusOK, status, string(raw))
		require.NotEmpty(t, tokens.RefreshToken)
		refreshed := n.Refresh(t, flow.ClientID, flow.ClientSecret, tokens)
		require.NotEmpty(t, refreshed.AccessToken)

		s, b := n.api(http.MethodGet, "/me/oauth-consents", signedIn.AccessToken, nil)
		require.Equal(t, http.StatusOK, s, string(b))
		var page iam.ListPage[iam.OAuthConsent]
		require.NoError(t, json.Unmarshal(b, &page))
		require.Len(t, page.Items, 1)
		require.Equal(t, created.ClientID, page.Items[0].ClientID)
		require.NotNil(t, page.Items[0].GroupName)

		s, b = n.api(http.MethodDelete, "/me/oauth-consents/"+created.ClientID, signedIn.AccessToken, nil)
		require.Equal(t, http.StatusNoContent, s, string(b))
		status, raw = n.Token(t, authtest.TokenRequest{ClientID: flow.ClientID, ClientSecret: flow.ClientSecret,
			Params: url.Values{"grant_type": {"refresh_token"}, "refresh_token": {refreshed.RefreshToken}}})
		require.Equal(t, http.StatusBadRequest, status, string(raw))
		require.Contains(t, string(raw), "invalid_grant")

		select {
		case token := <-logouts:
			res, err := n.HTTPClient().Get(n.URL + iam.JWKSPath)
			require.NoError(t, err)
			var set keys.JWKS
			require.NoError(t, json.NewDecoder(res.Body).Decode(&set))
			res.Body.Close()
			public, err := keys.PublicKeys(set)
			require.NoError(t, err)
			typ, claims, err := jose.Verify(token, func(_, kid string, _ map[string]any) (crypto.PublicKey, error) { return public[kid], nil })
			require.NoError(t, err, "the logout token is signed by the issuer")
			require.Equal(t, "logout+jwt", typ)
			require.Equal(t, n.URL, claims["iss"])
			require.Equal(t, shopper.ID, claims["sub"])
			require.Equal(t, created.ClientID, claims["aud"])
			require.Contains(t, claims["events"], "http://schemas.openid.net/event/backchannel-logout")
		case <-time.After(30 * time.Second):
			t.Fatal("no back-channel logout")
		}
		require.Eventually(t, func() bool {
			n.mu.Lock()
			defer n.mu.Unlock()
			for _, e := range n.events {
				if e.Kind == iam.EventOAuthConsentRevoked && e.UserID == shopper.ID && e.ClientID == created.ClientID && e.GroupID == groupA.ID() {
					return true
				}
			}
			return false
		}, 30*time.Second, 200*time.Millisecond)

		_, s, b = n.authorize(flow, signedIn, false)
		require.Equal(t, http.StatusConflict, s, "withdrawn consent is asked for again: %s", b)
		require.ErrorIs(t, n.Client.RevokeConsent(ctx, shopper.ID, created.ClientID), iam.ErrOAuthConsentNotFound)
	})

	t.Run("a disabled client and a deleted group are refused at once", func(t *testing.T) {
		verifier, _, b := n.authorize(flow, signedIn, true)
		status, tokens, raw := n.redeem(flow, verifier, b, nil)
		require.Equal(t, http.StatusOK, status, string(raw))
		authenticate := func() error {
			req := httptest.NewRequest(http.MethodGet, merchantAPI+"/v1/me", nil)
			req.Header.Set("Authorization", "Bearer "+tokens.AccessToken)
			_, err := n.Client.Authenticator().Authenticate(req)
			return err
		}
		require.NoError(t, authenticate())
		_, err := n.Client.UpdateGroupOAuthClient(ctx, iam.SystemIdentity(), groupA, created.ClientID, iam.OAuthClientUpdate{Disabled: ptr(true)})
		require.NoError(t, err)
		require.Error(t, authenticate(), "a disabled client's token")
		status, raw = n.Token(t, authtest.TokenRequest{ClientID: flow.ClientID, ClientSecret: flow.ClientSecret,
			Params: url.Values{"grant_type": {"refresh_token"}, "refresh_token": {tokens.RefreshToken}}})
		require.Equal(t, http.StatusUnauthorized, status, string(raw))
		_, err = n.Client.UpdateGroupOAuthClient(ctx, iam.SystemIdentity(), groupA, created.ClientID, iam.OAuthClientUpdate{Disabled: ptr(false)})
		require.NoError(t, err)
		require.NoError(t, authenticate())

		require.NoError(t, n.Client.DeleteGroup(ctx, groupA))
		require.Error(t, authenticate(), "a deleted group's client")
	})
}

// TestSecurityGroupOAuthClientAuthentication: a private_key_jwt client
// proves itself with a once-only RFC 7523 assertion signed by a key its
// jwks_uri publishes; a public client sends no secret, only PKCE.
func TestSecurityGroupOAuthClientAuthentication(t *testing.T) {
	n := newNetwork(t)
	ctx := context.Background()
	group, _, _ := n.group()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	jwks := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(keys.JWKS{Keys: []keys.JWK{keys.PublicJWK(&key.PublicKey, "merchant-1", "ES256")}})
	}))
	t.Cleanup(jwks.Close)
	pkj, err := n.Client.CreateGroupOAuthClient(ctx, iam.SystemIdentity(), group, iam.NewOAuthClient{ClientName: "Backend",
		RedirectURIs: []string{"https://shop.test/cb"}, TokenEndpointAuthMethod: iam.OAuthClientPrivateKeyJWT, JWKSURI: jwks.URL + "/jwks.json", Scope: "openid"})
	require.NoError(t, err)
	require.Nil(t, pkj.ClientSecret)
	spa, err := n.Client.CreateGroupOAuthClient(ctx, iam.SystemIdentity(), group, iam.NewOAuthClient{ClientName: "SPA",
		RedirectURIs: []string{"https://shop.test/spa"}, TokenEndpointAuthMethod: iam.OAuthClientNone, Scope: "openid"})
	require.NoError(t, err)
	shopper := authtest.NewUser(t, n.Client)
	require.NoError(t, n.Client.AcceptAgreements(ctx, shopper.ID, []iam.AgreementRef{termsV1}))
	signedIn := authtest.SignIn(t, n.Client, shopper)
	signer, err := keys.SignerFromKey("merchant-1", key)
	require.NoError(t, err)
	assertion := func(aud, jti string) string {
		now := time.Now()
		token, err := jose.Sign(ctx, signer, "JWT", map[string]any{"iss": pkj.ClientID, "sub": pkj.ClientID, "aud": aud,
			"iat": now.Unix(), "exp": now.Add(2 * time.Minute).Unix(), "jti": jti})
		require.NoError(t, err)
		return token
	}

	t.Run("private_key_jwt", func(t *testing.T) {
		flow := authtest.CodeFlow{ClientID: pkj.ClientID, RedirectURI: "https://shop.test/cb", Scopes: []string{"openid"}}
		verifier, s, b := n.authorize(flow, signedIn, true)
		require.Equal(t, http.StatusOK, s, string(b))
		jti := strings.Repeat("j", 16) + randomSuffix()
		form := url.Values{"client_assertion_type": {"urn:ietf:params:oauth:client-assertion-type:jwt-bearer"}, "client_assertion": {assertion(n.TokenEndpoint(), jti)}}
		status, tokens, raw := n.redeem(flow, verifier, b, form)
		require.Equal(t, http.StatusOK, status, string(raw))
		require.NotEmpty(t, tokens.IDToken)

		for name, a := range map[string]string{
			"a replayed assertion":    assertion(n.TokenEndpoint(), jti),
			"another audience":        assertion("https://elsewhere.test/token", strings.Repeat("k", 16)+randomSuffix()),
			"no assertion, no secret": "",
		} {
			verifier, _, b := n.authorize(flow, signedIn, false)
			form := url.Values{}
			if a != "" {
				form = url.Values{"client_assertion_type": {"urn:ietf:params:oauth:client-assertion-type:jwt-bearer"}, "client_assertion": {a}}
			}
			status, _, raw := n.redeem(flow, verifier, b, form)
			require.Equal(t, http.StatusUnauthorized, status, "%s: %s", name, raw)
		}
	})

	t.Run("a public client", func(t *testing.T) {
		flow := authtest.CodeFlow{ClientID: spa.ClientID, RedirectURI: "https://shop.test/spa", Scopes: []string{"openid"}}
		verifier, s, b := n.authorize(flow, signedIn, true)
		require.Equal(t, http.StatusOK, s, string(b))
		status, tokens, raw := n.redeem(flow, verifier, b, nil)
		require.Equal(t, http.StatusOK, status, string(raw))
		require.NotEmpty(t, tokens.AccessToken)
		verifier, _, b = n.authorize(flow, signedIn, false)
		withSecret := flow
		withSecret.ClientSecret = "guessed"
		status, _, raw = n.redeem(withSecret, verifier, b, nil)
		require.Equal(t, http.StatusUnauthorized, status, string(raw))
	})
}

func ptr[T any](v T) *T { return &v }

func must[T any](v T, err error) T {
	if err != nil {
		panic(err)
	}
	return v
}

// TestSecurityNetworkLinkProofs: what a network host (OpenRails linking a
// merchant's customer to a network account) checks in process: an ID token
// of a group client's flow, verified live; the client and scopes an access
// token was granted; and a withdrawal of consent it may refuse, which its own
// unlink is not.
func TestSecurityNetworkLinkProofs(t *testing.T) {
	n := newNetwork(t)
	ctx := context.Background()
	require.NotNil(t, n.Outbox, "Attach finds authtest's outbox")
	group, _, _ := n.group()
	created, err := n.Client.CreateGroupOAuthClient(ctx, iam.SystemIdentity(), group, iam.NewOAuthClient{ClientName: "Shop",
		RedirectURIs: []string{"https://shop.test/cb"}, TokenEndpointAuthMethod: iam.OAuthClientSecretBasic, Scope: "openid email openrails:link"})
	require.NoError(t, err)
	shopper := authtest.NewUser(t, n.Client)
	require.NoError(t, n.Client.AcceptAgreements(ctx, shopper.ID, []iam.AgreementRef{termsV1}))
	signedIn := authtest.SignIn(t, n.Client, shopper)
	flow := authtest.CodeFlow{ClientID: created.ClientID, ClientSecret: *created.ClientSecret, RedirectURI: "https://shop.test/cb",
		Scopes: []string{"openid", "openrails:link"}, Resource: merchantAPI, Nonce: "challenge-" + randomSuffix(), Consent: true}
	tokens := n.AuthorizeAs(t, signedIn, flow)

	t.Run("the ID token, verified in process", func(t *testing.T) {
		id, err := n.Client.VerifyIDToken(ctx, tokens.IDToken)
		require.NoError(t, err)
		require.Equal(t, shopper.ID, id.Subject)
		require.Equal(t, created.ClientID, id.ClientID)
		require.Equal(t, group.ID(), id.GroupID)
		require.Equal(t, flow.Nonce, id.Nonce)
		require.NotEmpty(t, id.SessionID)
		require.WithinDuration(t, time.Now(), id.AuthTime, time.Minute)
		require.NotEmpty(t, id.AMR)
		require.True(t, id.ExpiresAt.After(id.IssuedAt))

		parts := strings.Split(tokens.IDToken, ".")
		forged := parts[0] + "." + strings.Split(tokens.AccessToken, ".")[1] + "." + parts[2]
		for name, raw := range map[string]string{"an access token": tokens.AccessToken, "a forged payload": forged, "garbage": "a.b.c", "nothing": ""} {
			_, err := n.Client.VerifyIDToken(ctx, raw)
			require.ErrorIs(t, err, iam.ErrInvalidIDToken, name)
		}
	})

	t.Run("an access token names its client and granted scopes", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, merchantAPI+"/v1/me", nil)
		req.Header.Set("Authorization", "Bearer "+tokens.AccessToken)
		v, err := n.Client.Authenticator().Authenticate(req)
		require.NoError(t, err)
		granted, ok := v.(interface {
			ClientID() string
			Scopes() []string
		})
		require.True(t, ok)
		require.Equal(t, created.ClientID, granted.ClientID())
		require.ElementsMatch(t, []string{"openid", "openrails:link"}, granted.Scopes(), "openrails:self was not granted")
		require.Equal(t, n.URL, v.Identity().Issuer)
	})

	t.Run("the host may refuse a user's withdrawal of consent, never its own", func(t *testing.T) {
		var asked int
		n.mu.Lock()
		n.consentCheck = func(_ context.Context, userID, clientID string) error {
			asked++
			if userID == shopper.ID && clientID == created.ClientID {
				return iam.RefuseConsentRevocation("subscriptions_active")
			}
			return nil
		}
		n.mu.Unlock()
		s, b := n.api(http.MethodDelete, "/me/oauth-consents/"+created.ClientID, signedIn.AccessToken, nil)
		require.Equal(t, http.StatusConflict, s, string(b))
		require.Equal(t, "consent_revocation_refused", errorCode(t, b))
		require.Contains(t, string(b), `"reason":"subscriptions_active"`)
		require.Len(t, must(n.Client.OAuthConsents(ctx, shopper.ID)), 1)

		s, b = n.api(http.MethodDelete, "/me/oauth-consents/goc_"+strings.Repeat("a", 26), signedIn.AccessToken, nil)
		require.Equal(t, http.StatusNotFound, s, string(b))
		require.Equal(t, 1, asked, "no consent, no question")

		n.mu.Lock()
		n.consentCheck = func(context.Context, string, string) error { return io.ErrUnexpectedEOF }
		n.mu.Unlock()
		s, b = n.api(http.MethodDelete, "/me/oauth-consents/"+created.ClientID, signedIn.AccessToken, nil)
		require.Equal(t, http.StatusInternalServerError, s, "a failing check fails closed: %s", b)
		require.Len(t, must(n.Client.OAuthConsents(ctx, shopper.ID)), 1)

		require.NoError(t, n.Client.RevokeConsent(ctx, shopper.ID, created.ClientID), "the host's unlink is not asked")
		require.Empty(t, must(n.Client.OAuthConsents(ctx, shopper.ID)))
		n.mu.Lock()
		n.consentCheck = nil
		n.mu.Unlock()
	})

	t.Run("an ID token outlives neither its client nor its sign-in", func(t *testing.T) {
		fresh := n.AuthorizeAs(t, signedIn, flow)
		_, err := n.Client.VerifyIDToken(ctx, fresh.IDToken)
		require.NoError(t, err)
		_, err = n.Client.UpdateGroupOAuthClient(ctx, iam.SystemIdentity(), group, created.ClientID, iam.OAuthClientUpdate{Disabled: ptr(true)})
		require.NoError(t, err)
		_, err = n.Client.VerifyIDToken(ctx, fresh.IDToken)
		require.ErrorIs(t, err, iam.ErrInvalidIDToken, "a disabled client")
		_, err = n.Client.UpdateGroupOAuthClient(ctx, iam.SystemIdentity(), group, created.ClientID, iam.OAuthClientUpdate{Disabled: ptr(false)})
		require.NoError(t, err)
		id, err := n.Client.VerifyIDToken(ctx, fresh.IDToken)
		require.NoError(t, err)
		require.NoError(t, n.Client.RevokeSession(ctx, iam.SystemIdentity(), shopper.ID, id.SessionID))
		_, err = n.Client.VerifyIDToken(ctx, fresh.IDToken)
		require.ErrorIs(t, err, iam.ErrInvalidIDToken, "an ended sign-in")
	})
}
