package authprovider

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	jwt "github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/require"

	"github.com/open-rails/authkit/jwtkit"
)

func TestBuiltInsOwnTheirTraits(t *testing.T) {
	google := Google("id", "secret")
	require.Equal(t, "google", google.Name())
	require.Equal(t, "Google", google.DisplayName())
	require.Equal(t, "https://accounts.google.com", google.Issuer())
	require.True(t, google.PKCE())
	require.False(t, google.ResponseModeFormPost())
	require.True(t, google.SupportsStepUp())
	require.NoError(t, google.Validate())

	apple := Apple("id", AppleSecret{Static: "jwt"})
	require.Equal(t, "Apple", apple.DisplayName())
	require.True(t, apple.ResponseModeFormPost())
	require.False(t, apple.PKCE())
	require.True(t, apple.SupportsStepUp())
	require.Equal(t, []string{"openid", "email", "name"}, apple.(*oidcProvider).scopes)
	require.NoError(t, apple.Validate())

	// #294: OAuth2 IdPs silently re-authorize an approved app; never a step-up.
	discord := Discord("id", "secret")
	require.Equal(t, "Discord", discord.DisplayName())
	require.False(t, discord.SupportsStepUp())
	require.False(t, discord.PKCE())
	require.Equal(t, "https://discord.com", discord.Issuer())
	github := GitHub("id", "secret", WithScopes("read:user"), WithDisplayName("GH"))
	require.Equal(t, "GH", github.DisplayName())
	require.True(t, github.PKCE())
	require.False(t, github.SupportsStepUp())
	require.Equal(t, []string{"read:user"}, github.(*oauth2Provider).scopes)

	custom := OIDC("  MyIdP ", "https://idp.example", "id", "secret", WithScopes("email"))
	require.Equal(t, "myidp", custom.Name())
	require.Equal(t, "myidp", custom.DisplayName())
	require.Equal(t, []string{"openid", "email"}, custom.(*oidcProvider).scopes)
}

func TestValidateFailsClosed(t *testing.T) {
	for name, p := range map[string]Provider{
		"no client id":  Google("", "secret"),
		"empty secret":  Google("id", "  "),
		"no name":       OIDC("", "https://idp.example", "id", "secret"),
		"no issuer":     OIDC("x", "", "id", "secret"),
		"no userinfo":   OAuth2("x", "https://x.example", Endpoint{AuthorizeURL: "https://x.example/a", TokenURL: "https://x.example/t"}, "id", "secret", nil),
		"apple bad key": Apple("id", AppleSecret{TeamID: "T", KeyID: "K", PrivateKeyPEM: []byte("not a key")}),
		"apple no key":  Apple("id", AppleSecret{}),
	} {
		require.ErrorIs(t, p.Validate(), ErrProviderInvalid, name)
	}
	for name, ep := range map[string]Endpoint{
		"http authorize": {AuthorizeURL: "http://x.example/a", TokenURL: "https://x.example/t"},
		"http token":     {AuthorizeURL: "https://x.example/a", TokenURL: "http://x.example/t"},
		"no token":       {AuthorizeURL: "https://x.example/a"},
	} {
		p := OAuth2("x", "https://x.example", ep, "id", "secret", func(context.Context, *http.Client) (Identity, error) { return Identity{}, nil })
		require.ErrorIs(t, p.Validate(), ErrProviderNonHTTPSURL, name)
	}
}

func TestAppleKeySecretMintsES256ClientSecret(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	der, err := x509.MarshalPKCS8PrivateKey(key)
	require.NoError(t, err)
	p := Apple("com.example.app", AppleSecret{TeamID: "TEAM123", KeyID: "KEY456", PrivateKeyPEM: pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), TTL: time.Minute})
	require.NoError(t, p.Validate())

	secret, err := p.(*oidcProvider).clientSecret(context.Background())
	require.NoError(t, err)
	tok, err := jwt.Parse(secret, func(t *jwt.Token) (any, error) { return &key.PublicKey, nil }, jwt.WithValidMethods([]string{"ES256"}))
	require.NoError(t, err)
	claims := tok.Claims.(jwt.MapClaims)
	require.Equal(t, "TEAM123", claims["iss"])
	require.Equal(t, "com.example.app", claims["sub"])
	require.Equal(t, "https://appleid.apple.com", claims["aud"])
	require.Equal(t, "KEY456", tok.Header["kid"])
	exp, _ := claims["exp"].(float64)
	require.InDelta(t, time.Now().Add(time.Minute).Unix(), exp, 5)
}

type recordingTransport struct {
	mu   sync.Mutex
	seen []string
}

func (t *recordingTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	t.mu.Lock()
	t.seen = append(t.seen, r.URL.Path)
	t.mu.Unlock()
	return http.DefaultTransport.RoundTrip(r)
}

// The exchange posts client credentials, code, redirect_uri and the PKCE
// verifier; userinfo runs with the bearer token; GitHub's subject is the
// numeric id and the verified address comes only from /user/emails.
func TestOAuth2ExchangeAndGitHubUserInfo(t *testing.T) {
	var form url.Values
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/token":
			require.NoError(t, r.ParseForm())
			form = r.PostForm
			_ = json.NewEncoder(w).Encode(map[string]any{"access_token": "gh-token", "token_type": "bearer", "scope": "read:user,user:email"})
		case "/user":
			require.Equal(t, "Bearer gh-token", r.Header.Get("Authorization"))
			require.Equal(t, gitHubAccept, r.Header.Get("Accept"))
			_ = json.NewEncoder(w).Encode(map[string]any{"id": 12345, "login": "octocat", "name": "Mona Lisa", "email": "public@example.com"})
		case "/user/emails":
			_ = json.NewEncoder(w).Encode([]map[string]any{
				{"email": "secondary@example.com", "primary": false, "verified": true},
				{"email": "octocat@example.com", "primary": true, "verified": true},
			})
		default:
			http.NotFound(w, r)
		}
	}))
	defer ts.Close()

	rt := &recordingTransport{}
	p := OAuth2("github", "https://github.com/login/oauth", Endpoint{AuthorizeURL: ts.URL + "/authorize", TokenURL: ts.URL + "/token"},
		"client-id", "client-secret", gitHubUserInfo(ts.URL), WithPKCE(true), WithHTTPClient(&http.Client{Transport: rt, Timeout: 5 * time.Second}))

	authURL, err := p.AuthCodeURL(context.Background(), AuthRequest{State: "st", CodeChallenge: "chal", RedirectURI: "https://auth.example/oidc/github/callback"})
	require.NoError(t, err)
	u, err := url.Parse(authURL)
	require.NoError(t, err)
	require.Equal(t, ts.URL+"/authorize", u.Scheme+"://"+u.Host+u.Path)
	require.Equal(t, "chal", u.Query().Get("code_challenge"))
	require.Equal(t, "S256", u.Query().Get("code_challenge_method"))
	require.Equal(t, "st", u.Query().Get("state"))
	require.Equal(t, "client-id", u.Query().Get("client_id"))

	identity, err := p.Exchange(context.Background(), ExchangeRequest{Code: "oauth-code", CodeVerifier: "pkce-verifier", RedirectURI: "https://auth.example/oidc/github/callback"})
	require.NoError(t, err)
	require.Equal(t, "client-id", form.Get("client_id"))
	require.Equal(t, "client-secret", form.Get("client_secret"))
	require.Equal(t, "authorization_code", form.Get("grant_type"))
	require.Equal(t, "oauth-code", form.Get("code"))
	require.Equal(t, "https://auth.example/oidc/github/callback", form.Get("redirect_uri"))
	require.Equal(t, "pkce-verifier", form.Get("code_verifier"))
	require.Equal(t, Identity{Subject: "12345", Email: "octocat@example.com", EmailVerified: true, PreferredUsername: "octocat", DisplayName: "Mona Lisa"}, identity)
	require.Equal(t, []string{"/token", "/user", "/user/emails"}, rt.seen, "every call goes through the configured client")
}

// AK security audit F4: GitHub's public profile email is never reported verified.
func TestGitHubPublicEmailIsNeverVerified(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/user":
			_ = json.NewEncoder(w).Encode(map[string]any{"id": "77", "login": "pub", "email": "public@example.com"})
		case "/user/emails":
			_ = json.NewEncoder(w).Encode([]map[string]any{{"email": "public@example.com", "primary": true, "verified": false}})
		default:
			http.NotFound(w, r)
		}
	}))
	defer ts.Close()
	identity, err := gitHubUserInfo(ts.URL)(context.Background(), ts.Client())
	require.NoError(t, err)
	require.Equal(t, "public@example.com", identity.Email)
	require.False(t, identity.EmailVerified)
}

func TestDiscordUserInfo(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"id": "123", "username": "gamer", "global_name": "Gamer", "email": "g@example.com", "verified": true})
	}))
	defer ts.Close()
	identity, err := discordUserInfo(ts.URL)(context.Background(), ts.Client())
	require.NoError(t, err)
	require.Equal(t, Identity{Subject: "123", Email: "g@example.com", EmailVerified: true, PreferredUsername: "gamer", DisplayName: "Gamer"}, identity)
}

// fakeOIDC is a minimal OpenID Provider: discovery, JWKS and a token endpoint
// that signs an id_token carrying the recorded nonce.
type fakeOIDC struct {
	srv       *httptest.Server
	key       *rsa.PrivateKey
	discovery atomic.Int32
	mu        sync.Mutex
	nonce     string
	secret    string
	verifier  string
}

func newFakeOIDC(t *testing.T) *fakeOIDC {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	f := &fakeOIDC{key: key}
	f.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/.well-known/openid-configuration":
			f.discovery.Add(1)
			_ = json.NewEncoder(w).Encode(map[string]any{
				"issuer": f.srv.URL, "authorization_endpoint": f.srv.URL + "/authorize", "token_endpoint": f.srv.URL + "/token",
				"jwks_uri": f.srv.URL + "/jwks", "id_token_signing_alg_values_supported": []string{"RS256"},
			})
		case "/jwks":
			_ = json.NewEncoder(w).Encode(jwtkit.JWKS{Keys: []jwtkit.JWK{jwtkit.PublicToJWK(&key.PublicKey, "kid", "RS256")}})
		case "/token":
			require.NoError(t, r.ParseForm())
			f.mu.Lock()
			f.secret = r.PostForm.Get("client_secret")
			if _, pw, ok := r.BasicAuth(); ok {
				f.secret = pw
			}
			f.verifier = r.PostForm.Get("code_verifier")
			nonce := f.nonce
			f.mu.Unlock()
			now := time.Now()
			tok := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{
				"iss": f.srv.URL, "aud": "client", "sub": "subject-1", "nonce": nonce,
				"iat": now.Add(-time.Second).Unix(), "exp": now.Add(time.Minute).Unix(), "auth_time": now.Add(-2 * time.Second).Unix(),
				"email": "user@example.com", "email_verified": true, "name": "User One", "preferred_username": "user1",
			})
			tok.Header["kid"] = "kid"
			signed, err := tok.SignedString(key)
			require.NoError(t, err)
			_ = json.NewEncoder(w).Encode(map[string]any{"access_token": "at", "token_type": "Bearer", "id_token": signed})
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(f.srv.Close)
	return f
}

func TestOIDCAuthCodeURLAndExchange(t *testing.T) {
	idp := newFakeOIDC(t)
	calls := 0
	p := OIDC("custom", idp.srv.URL, "client", "", WithSecret(SecretFunc(func(context.Context) (string, error) {
		calls++
		return "minted-secret", nil
	})))
	require.NoError(t, p.Validate())
	const redirect = "https://auth.example/oidc/custom/callback"

	authURL, err := p.AuthCodeURL(context.Background(), AuthRequest{State: "st", Nonce: "n1", CodeChallenge: "chal", RedirectURI: redirect, Params: map[string]string{"max_age": "0"}})
	require.NoError(t, err)
	u, err := url.Parse(authURL)
	require.NoError(t, err)
	q := u.Query()
	require.Equal(t, idp.srv.URL+"/authorize", u.Scheme+"://"+u.Host+u.Path)
	require.Equal(t, "n1", q.Get("nonce"))
	require.Equal(t, "chal", q.Get("code_challenge"))
	require.Equal(t, "S256", q.Get("code_challenge_method"))
	require.Equal(t, "0", q.Get("max_age"))
	require.Equal(t, redirect, q.Get("redirect_uri"))
	require.Contains(t, q.Get("scope"), "openid")

	idp.mu.Lock()
	idp.nonce = "n1"
	idp.mu.Unlock()
	identity, err := p.Exchange(context.Background(), ExchangeRequest{Code: "code", CodeVerifier: "ver", Nonce: "n1", RedirectURI: redirect})
	require.NoError(t, err)
	require.Equal(t, "subject-1", identity.Subject)
	require.Equal(t, "user@example.com", identity.Email)
	require.True(t, identity.EmailVerified)
	require.Equal(t, "User One", identity.DisplayName)
	require.Equal(t, "user1", identity.PreferredUsername)
	require.WithinDuration(t, time.Now(), identity.AuthTime, 10*time.Second)
	require.Equal(t, "minted-secret", idp.secret, "the per-exchange secret reaches the token endpoint")
	require.Equal(t, "ver", idp.verifier)
	require.Equal(t, 1, calls)

	// A nonce the flow never issued is refused.
	_, err = p.Exchange(context.Background(), ExchangeRequest{Code: "code", Nonce: "other", RedirectURI: redirect})
	require.Error(t, err)

	// Discovery ran once for the redirect URI; the relying party is reused.
	_, err = p.AuthCodeURL(context.Background(), AuthRequest{State: "st2", Nonce: "n2", RedirectURI: redirect})
	require.NoError(t, err)
	require.Equal(t, int32(1), idp.discovery.Load())
}
