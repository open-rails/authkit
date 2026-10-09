package authtest

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"sync"
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
// confidential client; Resource, Scopes ("offline_access" for an offline
// grant) and AuthorizationDetails (an RFC 9396 JSON array) are what the
// client asks for. DPoP binds the tokens to a key, and the grant to it for a
// key-bound client: a public client always has one (Authorize makes it when
// nil).
type CodeFlow struct {
	ClientID             string
	ClientSecret         string
	RedirectURI          string
	Resource             string
	Scopes               []string
	Nonce                string
	AuthorizationDetails string
	DPoP                 *DPoPKey
	// Prompt ("login") and MaxAge (seconds; 0 is now) ask for a fresh
	// sign-in: approving with an older one answers step_up_required.
	Prompt string
	MaxAge *int
}

// OAuthTokens is the token endpoint's answer. DPoP is the key the tokens
// are bound to, nil for bearer tokens.
type OAuthTokens struct {
	AccessToken     string   `json:"access_token"`
	TokenType       string   `json:"token_type"`
	ExpiresIn       int64    `json:"expires_in"`
	Scope           string   `json:"scope"`
	IDToken         string   `json:"id_token"`
	RefreshToken    string   `json:"refresh_token"`
	IssuedTokenType string   `json:"issued_token_type"`
	DPoP            *DPoPKey `json:"-"`
	// AuthorizationDetails is the grant's RFC 9396 array, when it has one.
	AuthorizationDetails json.RawMessage `json:"authorization_details"`
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
	if f.DPoP == nil && f.ClientSecret == "" {
		f.DPoP = NewDPoPKey(t)
	}
	callback, verifier := as.consent(t, signedIn, f)
	code := callback.Query().Get("code")
	if code == "" {
		t.Fatalf("authtest: authorize: redirect carries no code: %s", callback)
	}
	return as.mustToken(t, "authorize", TokenRequest{ClientID: f.ClientID, ClientSecret: f.ClientSecret, DPoP: f.DPoP, Params: url.Values{
		"grant_type": {"authorization_code"}, "code": {code}, "redirect_uri": {f.RedirectURI},
		"code_verifier": {verifier}, "resource": nonEmptyValues(f.Resource),
	}})
}

// Consent runs f's authorization request and the SPA's approval for
// signedIn, and returns the client redirect: its code, or the error a
// refusal (the grant authorizer's: access_denied) sends back.
func (as *AuthorizationServer) Consent(t testing.TB, signedIn iam.TokenSet, f CodeFlow) *url.URL {
	t.Helper()
	callback, _ := as.consent(t, signedIn, f)
	return callback
}

func (as *AuthorizationServer) consent(t testing.TB, signedIn iam.TokenSet, f CodeFlow) (*url.URL, string) {
	t.Helper()
	verifier := pkceVerifier()
	state := pkceVerifier()[:16]
	id := as.BeginAuthorization(t, f, verifier, state)
	location := as.Approve(t, signedIn.AccessToken, id)
	callback, err := url.Parse(location)
	if err != nil || callback.Query().Get("state") != state || callback.Query().Get("iss") != as.URL {
		t.Fatalf("authtest: authorize: redirect %q does not answer the request", location)
	}
	return callback, verifier
}

// Refresh redeems tokens' refresh token as clientID (with clientSecret for
// a confidential client), proving tokens' DPoP key, and returns the rotated
// tokens.
func (as *AuthorizationServer) Refresh(t testing.TB, clientID, clientSecret string, tokens OAuthTokens) OAuthTokens {
	t.Helper()
	return as.mustToken(t, "refresh", TokenRequest{ClientID: clientID, ClientSecret: clientSecret, DPoP: tokens.DPoP, Params: url.Values{
		"grant_type": {"refresh_token"}, "refresh_token": {tokens.RefreshToken},
	}})
}

// TokenExchange is an RFC 8693 request: SubjectToken, the user's AuthKit
// access token (SignIn's), for an access token to Resource.
type TokenExchange struct {
	ClientID             string
	ClientSecret         string
	SubjectToken         string
	Resource             string
	Scopes               []string
	AuthorizationDetails string
	DPoP                 *DPoPKey
}

// Exchange runs a token exchange and fails the test on a refusal. A public
// client without a key gets a fresh one.
func (as *AuthorizationServer) Exchange(t testing.TB, x TokenExchange) OAuthTokens {
	t.Helper()
	if x.DPoP == nil && x.ClientSecret == "" {
		x.DPoP = NewDPoPKey(t)
	}
	return as.mustToken(t, "exchange", TokenRequest{ClientID: x.ClientID, ClientSecret: x.ClientSecret, DPoP: x.DPoP, Params: url.Values{
		"grant_type": {"urn:ietf:params:oauth:grant-type:token-exchange"}, "subject_token": {x.SubjectToken},
		"subject_token_type": {"urn:ietf:params:oauth:token-type:access_token"}, "resource": nonEmptyValues(x.Resource),
		"scope": nonEmptyValues(strings.Join(x.Scopes, " ")), "authorization_details": nonEmptyValues(x.AuthorizationDetails),
	}})
}

// ClientCredentials gets a confidential client's own access token for
// resource; key, when set, binds it.
func (as *AuthorizationServer) ClientCredentials(t testing.TB, clientID, clientSecret, resource string, scopes []string, key *DPoPKey) OAuthTokens {
	t.Helper()
	return as.mustToken(t, "client credentials", TokenRequest{ClientID: clientID, ClientSecret: clientSecret, DPoP: key, Params: url.Values{
		"grant_type": {"client_credentials"}, "resource": nonEmptyValues(resource), "scope": nonEmptyValues(strings.Join(scopes, " ")),
	}})
}

// ClientCredentialsRequest is a confidential client's request for its own
// access token; DPoP, when set, binds it.
type ClientCredentialsRequest struct {
	ClientID             string
	ClientSecret         string
	Resource             string
	Scopes               []string
	AuthorizationDetails string
	DPoP                 *DPoPKey
}

// RequestClientCredentials is ClientCredentials with authorization_details,
// failing the test on a refusal.
func (as *AuthorizationServer) RequestClientCredentials(t testing.TB, r ClientCredentialsRequest) OAuthTokens {
	t.Helper()
	return as.mustToken(t, "client credentials", TokenRequest{ClientID: r.ClientID, ClientSecret: r.ClientSecret, DPoP: r.DPoP, Params: url.Values{
		"grant_type": {"client_credentials"}, "resource": nonEmptyValues(r.Resource), "scope": nonEmptyValues(strings.Join(r.Scopes, " ")),
		"authorization_details": nonEmptyValues(r.AuthorizationDetails),
	}})
}

// GrantAuthorizer is a recording grant authorizer: install it with
// WithDeps (d.OAuthGrants = g.Authorize). Decide answers each request; nil
// grants the defaults.
type GrantAuthorizer struct {
	Decide   func(iam.OAuthGrantRequest) (iam.OAuthGrantDecision, error)
	mu       sync.Mutex
	requests []iam.OAuthGrantRequest
}

// Authorize is the iam.OAuthGrantAuthorizer.
func (g *GrantAuthorizer) Authorize(_ context.Context, req iam.OAuthGrantRequest) (iam.OAuthGrantDecision, error) {
	g.mu.Lock()
	g.requests = append(g.requests, req)
	decide := g.Decide
	g.mu.Unlock()
	if decide == nil {
		return iam.OAuthGrantDecision{}, nil
	}
	return decide(req)
}

// Requests are the requests decided so far, oldest first.
func (g *GrantAuthorizer) Requests() []iam.OAuthGrantRequest {
	g.mu.Lock()
	defer g.mu.Unlock()
	return append([]iam.OAuthGrantRequest{}, g.requests...)
}

// Last is the latest request of kind; ok is false when there is none.
func (g *GrantAuthorizer) Last(kind iam.OAuthGrantKind) (req iam.OAuthGrantRequest, ok bool) {
	g.mu.Lock()
	defer g.mu.Unlock()
	for i := len(g.requests) - 1; i >= 0; i-- {
		if g.requests[i].Kind == kind {
			return g.requests[i], true
		}
	}
	return iam.OAuthGrantRequest{}, false
}

func (as *AuthorizationServer) mustToken(t testing.TB, what string, req TokenRequest) OAuthTokens {
	t.Helper()
	status, body := as.Token(t, req)
	var tokens OAuthTokens
	if status != http.StatusOK || json.Unmarshal(body, &tokens) != nil {
		t.Fatalf("authtest: %s: token: %d %s", what, status, body)
	}
	if tokens.TokenType == "DPoP" {
		tokens.DPoP = req.DPoP
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
		"resource": nonEmptyValues(f.Resource), "authorization_details": nonEmptyValues(f.AuthorizationDetails),
	}
	if f.DPoP != nil {
		q.Set("dpop_jkt", f.DPoP.Thumbprint())
	}
	if f.Prompt != "" {
		q.Set("prompt", f.Prompt)
	}
	if f.MaxAge != nil {
		q.Set("max_age", strconv.Itoa(*f.MaxAge))
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

// TokenRequest is one raw token endpoint request: Params as clientID (with
// Basic authentication when ClientSecret is set), with a DPoP proof of DPoP
// when set.
type TokenRequest struct {
	ClientID     string
	ClientSecret string
	Params       url.Values
	DPoP         *DPoPKey
}

// Token posts req to the token endpoint and returns the status and body.
func (as *AuthorizationServer) Token(t testing.TB, req TokenRequest) (int, []byte) {
	t.Helper()
	return as.post(t, iam.OAuthTokenPath, req)
}

// Revoke posts token to the revocation endpoint (RFC 7009) as clientID and
// returns the status.
func (as *AuthorizationServer) Revoke(t testing.TB, clientID, clientSecret, token string) int {
	t.Helper()
	status, _ := as.post(t, iam.OAuthRevocationPath, TokenRequest{ClientID: clientID, ClientSecret: clientSecret, Params: url.Values{"token": {token}}})
	return status
}

func (as *AuthorizationServer) post(t testing.TB, path string, r TokenRequest) (int, []byte) {
	t.Helper()
	params := url.Values{}
	for k, v := range r.Params {
		params[k] = v
	}
	if r.ClientSecret == "" {
		params.Set("client_id", r.ClientID)
	}
	req, _ := http.NewRequest(http.MethodPost, as.URL+path, strings.NewReader(params.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if r.ClientSecret != "" {
		req.SetBasicAuth(url.QueryEscape(r.ClientID), url.QueryEscape(r.ClientSecret))
	}
	if r.DPoP != nil {
		req.Header.Set("DPoP", r.DPoP.Proof(t, http.MethodPost, as.URL+path, "", ""))
	}
	res, err := as.HTTPClient().Do(req)
	if err != nil {
		t.Fatalf("authtest: %s: %v", path, err)
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
