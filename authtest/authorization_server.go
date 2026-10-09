package authtest

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/open-rails/authkit"
	"github.com/open-rails/authkit/iam"
)

// AuthorizationServer is an AuthKit authorization server (Config.
// AuthorizationServer) on an HTTPS test server, for testing a resource
// server or an OAuth client against real sign-ins and real tokens. URL is
// the issuer: its metadata (iam.OpenIDConfigurationPath), JWKS and OAuth
// endpoints are served beneath it, as in production.
type AuthorizationServer struct {
	// Client is the deployment's AuthKit Client: its users, roles and
	// sessions.
	Client *authkit.Client
	Outbox *Outbox
	// URL is the issuer: the HTTPS server's URL, without a trailing slash.
	URL    string
	server *httptest.Server
}

// NewAuthorizationServer serves New's Client over HTTPS (an httptest TLS
// server) with Token.Issuer set to the server's URL, so verifiers fetch its
// metadata and keys as they would from a deployment. Declare its clients and
// resource servers with WithConfig (Config.AuthorizationServer); opts apply
// after the issuer is set. It needs AUTHKIT_TEST_DATABASE_URL like New, and
// is closed at cleanup.
func NewAuthorizationServer(t testing.TB, opts ...Option) *AuthorizationServer {
	t.Helper()
	var handler atomic.Pointer[http.Handler]
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if h := handler.Load(); h != nil {
			(*h).ServeHTTP(w, r)
			return
		}
		http.Error(w, "starting", http.StatusServiceUnavailable)
	}))
	t.Cleanup(server.Close)
	issuer := server.URL
	opts = append([]Option{WithConfig(func(c *authkit.Config) {
		c.Token.Issuer = issuer
		c.Token.AllowPrivateNetworkJWKS = true
	})}, opts...)
	auth, outbox := New(t, opts...)
	h := auth.Handler()
	handler.Store(&h)
	return &AuthorizationServer{Client: auth, Outbox: outbox, URL: issuer, server: server}
}

// HTTPClient trusts the server's certificate and never follows a redirect,
// so a test reads each Location itself.
func (as *AuthorizationServer) HTTPClient() *http.Client {
	c := *as.server.Client()
	c.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	return &c
}

// CodeFlow is one authorization code request. ClientSecret is set for a
// confidential client; Resource and Scopes are what the client asks for.
type CodeFlow struct {
	ClientID     string
	ClientSecret string
	RedirectURI  string
	Resource     string
	Scopes       []string
	Nonce        string
}

// OAuthTokens is the token endpoint's answer.
type OAuthTokens struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int64  `json:"expires_in"`
	Scope        string `json:"scope"`
	IDToken      string `json:"id_token"`
	RefreshToken string `json:"refresh_token"`
}

// Authorize signs u in and runs the authorization code flow for it as a
// browser and the SPA would: the authorization request with PKCE, the SPA's
// approval for that sign-in, then the code's redemption at the token
// endpoint. It fails the test on any refusal.
func (as *AuthorizationServer) Authorize(t testing.TB, u User, f CodeFlow) OAuthTokens {
	t.Helper()
	return as.AuthorizeAs(t, SignIn(t, as.Client, u), f)
}

// AuthorizeAs is Authorize for a sign-in the test already holds.
func (as *AuthorizationServer) AuthorizeAs(t testing.TB, signedIn iam.TokenSet, f CodeFlow) OAuthTokens {
	t.Helper()
	verifier := pkceVerifier()
	state := pkceVerifier()[:16]
	id := as.BeginAuthorization(t, f, verifier, state)
	location := as.Approve(t, signedIn.AccessToken, id)
	callback, err := url.Parse(location)
	if err != nil || callback.Query().Get("state") != state || callback.Query().Get("iss") != as.URL {
		t.Fatalf("authtest: authorize: redirect %q does not answer the request", location)
	}
	code := callback.Query().Get("code")
	if code == "" {
		t.Fatalf("authtest: authorize: redirect carries no code: %s", location)
	}
	status, body := as.Token(t, f.ClientID, f.ClientSecret, url.Values{
		"grant_type": {"authorization_code"}, "code": {code}, "redirect_uri": {f.RedirectURI},
		"code_verifier": {verifier}, "resource": nonEmptyValues(f.Resource),
	})
	var tokens OAuthTokens
	if status != http.StatusOK || json.Unmarshal(body, &tokens) != nil {
		t.Fatalf("authtest: authorize: token: %d %s", status, body)
	}
	return tokens
}

// BeginAuthorization sends an authorization request with verifier's S256
// challenge and returns the pending request's id the server sent the
// browser to the SPA with.
func (as *AuthorizationServer) BeginAuthorization(t testing.TB, f CodeFlow, verifier, state string) string {
	t.Helper()
	q := url.Values{
		"response_type": {"code"}, "client_id": {f.ClientID}, "redirect_uri": {f.RedirectURI},
		"scope": {strings.Join(f.Scopes, " ")}, "state": {state}, "nonce": nonEmptyValues(f.Nonce),
		"code_challenge": {PKCEChallenge(verifier)}, "code_challenge_method": {"S256"},
		"resource": nonEmptyValues(f.Resource),
	}
	res, err := as.HTTPClient().Get(as.URL + iam.OAuthAuthorizePath + "?" + q.Encode())
	if err != nil {
		t.Fatalf("authtest: authorize: %v", err)
	}
	defer res.Body.Close()
	location, _ := url.Parse(res.Header.Get("Location"))
	if res.StatusCode != http.StatusSeeOther || location == nil || location.Query().Get("authorization") == "" {
		body, _ := io.ReadAll(res.Body)
		t.Fatalf("authtest: authorize: %d %s %s", res.StatusCode, res.Header.Get("Location"), body)
	}
	return location.Query().Get("authorization")
}

// Approve approves the pending request id with the sign-in accessToken
// belongs to, as the SPA does, and returns the client redirect.
func (as *AuthorizationServer) Approve(t testing.TB, accessToken, id string) string {
	t.Helper()
	req, _ := http.NewRequest(http.MethodPost, as.URL+as.Client.APIBase()+"/oauth2/authorizations/"+url.PathEscape(id)+"/approve", nil)
	req.Header.Set("Authorization", "Bearer "+accessToken)
	res, err := as.HTTPClient().Do(req)
	if err != nil {
		t.Fatalf("authtest: approve: %v", err)
	}
	defer res.Body.Close()
	body, _ := io.ReadAll(res.Body)
	var out struct {
		RedirectTo string `json:"redirect_to"`
	}
	if res.StatusCode != http.StatusOK || json.Unmarshal(body, &out) != nil {
		t.Fatalf("authtest: approve: %d %s", res.StatusCode, body)
	}
	return out.RedirectTo
}

// Token posts params to the token endpoint as clientID (with Basic
// authentication when clientSecret is set) and returns the status and body.
func (as *AuthorizationServer) Token(t testing.TB, clientID, clientSecret string, params url.Values) (int, []byte) {
	t.Helper()
	if clientSecret == "" {
		params.Set("client_id", clientID)
	}
	req, _ := http.NewRequest(http.MethodPost, as.URL+iam.OAuthTokenPath, strings.NewReader(params.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if clientSecret != "" {
		req.SetBasicAuth(url.QueryEscape(clientID), url.QueryEscape(clientSecret))
	}
	res, err := as.HTTPClient().Do(req)
	if err != nil {
		t.Fatalf("authtest: token: %v", err)
	}
	defer res.Body.Close()
	body, _ := io.ReadAll(res.Body)
	return res.StatusCode, body
}

// ClientSecretSHA256 is the OAuthClientConfig.SecretSHA256 of secret.
func ClientSecretSHA256(secret string) string {
	sum := sha256.Sum256([]byte(secret))
	return hex.EncodeToString(sum[:])
}

// PKCEChallenge is verifier's RFC 7636 S256 code challenge.
func PKCEChallenge(verifier string) string {
	sum := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

func pkceVerifier() string {
	b := make([]byte, 32)
	_, _ = rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}

func nonEmptyValues(v string) []string {
	if v == "" {
		return nil
	}
	return []string{v}
}
