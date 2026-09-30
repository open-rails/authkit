// Package testidp is a fake identity provider for tests of AuthKit's provider
// sign-in, link and recovery flows: an OpenID Provider (discovery, JWKS, ID
// tokens) and a plain OAuth2 server (token, userinfo) on one TLS server.
//
// The IdP keeps no state. A test reads the authorization request a flow start
// produced (Authorize), signs in there as an Identity (Code), and replays the
// IdP's redirect to AuthKit's callback. The code carries the identity and what
// the request bound it to: the nonce the ID token echoes, the redirect URI and
// the S256 challenge the token endpoint checks.
package testidp

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/open-rails/authkit/internal/jose"
	"github.com/open-rails/authkit/internal/testkeys"
	"github.com/open-rails/authkit/keys"
	"github.com/open-rails/authkit/provider"
)

// ClientSecret is the client secret every IdP accepts.
const ClientSecret = "testidp-secret"

// Identity is who signs in at the IdP.
type Identity struct {
	Subject string `json:"sub"`
	Email   string `json:"email,omitempty"`
	// EmailVerified asserts Email; false omits the claim.
	EmailVerified bool   `json:"email_verified,omitempty"`
	Username      string `json:"preferred_username,omitempty"`
	Name          string `json:"name,omitempty"`
}

// Authorization is what the IdP's authorization endpoint received: the state
// it hands back, and the nonce, redirect URI and S256 code challenge a code is
// bound to.
type Authorization struct {
	State         string
	Nonce         string
	RedirectURI   string
	CodeChallenge string
}

// Outage is how the IdP answers every request.
type Outage int32

const (
	Up          Outage = iota // serves normally
	Unavailable               // answers 503
	Reset                     // drops the connection
)

// IdP is a running identity provider, closed at the test's cleanup.
type IdP struct {
	Issuer   string
	ClientID string

	server *httptest.Server
	signer keys.Signer
	outage atomic.Int32
}

// New starts an IdP with its own signing key.
func New(t testing.TB) *IdP {
	t.Helper()
	p := &IdP{ClientID: "testidp-client", signer: testkeys.RSA("testidp")}
	p.server = httptest.NewTLSServer(http.HandlerFunc(p.serve))
	t.Cleanup(p.server.Close)
	p.Issuer = p.server.URL
	return p
}

// OIDC is an OpenID Connect provider named name for this IdP, trusted to
// verify email. opts come after the defaults.
func (p *IdP) OIDC(name string, opts ...provider.Option) provider.Provider {
	return provider.OIDC(name, p.Issuer, p.ClientID, ClientSecret, p.options(opts)...)
}

// OAuth2 is a plain OAuth2 provider named name for this IdP, reading the
// identity from its userinfo endpoint, trusted to verify email. opts come
// after the defaults.
func (p *IdP) OAuth2(name string, opts ...provider.Option) provider.Provider {
	ep := provider.Endpoint{AuthorizeURL: p.Issuer + "/authorize", TokenURL: p.Issuer + "/token"}
	return provider.OAuth2(name, p.Issuer, ep, p.ClientID, ClientSecret, p.userInfo, p.options(opts)...)
}

func (p *IdP) options(opts []provider.Option) []provider.Option {
	return append([]provider.Option{provider.WithTrustedEmailVerification(true), provider.WithHTTPClient(p.server.Client())}, opts...)
}

// SetOutage makes every endpoint fail as o says, until the next call.
func (p *IdP) SetOutage(o Outage) { p.outage.Store(int32(o)) }

// Authorize reads the authorization request a flow start sent the browser to;
// the test fails when authURL is not one for this IdP.
func (p *IdP) Authorize(t testing.TB, authURL string) Authorization {
	t.Helper()
	u, err := url.Parse(authURL)
	if err != nil || u.Scheme+"://"+u.Host+u.Path != p.Issuer+"/authorize" {
		t.Fatalf("testidp: %q is not this IdP's authorization endpoint", authURL)
	}
	q := u.Query()
	if q.Get("client_id") != p.ClientID || q.Get("response_type") != "code" || q.Get("state") == "" {
		t.Fatalf("testidp: malformed authorization request %s", authURL)
	}
	a := Authorization{State: q.Get("state"), Nonce: q.Get("nonce"), RedirectURI: q.Get("redirect_uri")}
	if challenge := q.Get("code_challenge"); challenge != "" {
		if q.Get("code_challenge_method") != "S256" {
			t.Fatalf("testidp: code challenge method %q", q.Get("code_challenge_method"))
		}
		a.CodeChallenge = challenge
	}
	return a
}

// Code is the authorization code for id signing in after a. The token
// endpoint redeems it for an ID token naming id with a's nonce, only for a's
// redirect URI and, when a carries a code challenge, only with its verifier.
func (p *IdP) Code(id Identity, a Authorization) string {
	raw, _ := json.Marshal(grant{Identity: id, Nonce: a.Nonce, RedirectURI: a.RedirectURI, CodeChallenge: a.CodeChallenge})
	return base64.RawURLEncoding.EncodeToString(raw)
}

// Redirect is the query of the IdP's redirect back to the callback once id
// signs in at authURL: its state and code.
func (p *IdP) Redirect(t testing.TB, authURL string, id Identity) url.Values {
	t.Helper()
	a := p.Authorize(t, authURL)
	return url.Values{"state": {a.State}, "code": {p.Code(id, a)}}
}

// grant is what a code carries.
type grant struct {
	Identity
	Nonce         string `json:"nonce,omitempty"`
	RedirectURI   string `json:"redirect_uri,omitempty"`
	CodeChallenge string `json:"code_challenge,omitempty"`
}

func decode(code string) (grant, bool) {
	var g grant
	raw, err := base64.RawURLEncoding.DecodeString(code)
	if err != nil || json.Unmarshal(raw, &g) != nil || g.Subject == "" {
		return grant{}, false
	}
	return g, true
}

func (p *IdP) serve(w http.ResponseWriter, r *http.Request) {
	switch Outage(p.outage.Load()) {
	case Unavailable:
		w.WriteHeader(http.StatusServiceUnavailable)
		return
	case Reset:
		if conn, _, err := w.(http.Hijacker).Hijack(); err == nil {
			_ = conn.Close()
		}
		return
	}
	switch r.URL.Path {
	case "/.well-known/openid-configuration":
		writeJSON(w, http.StatusOK, map[string]any{
			"issuer":                                p.Issuer,
			"authorization_endpoint":                p.Issuer + "/authorize",
			"token_endpoint":                        p.Issuer + "/token",
			"userinfo_endpoint":                     p.Issuer + "/userinfo",
			"jwks_uri":                              p.Issuer + "/jwks",
			"response_types_supported":              []string{"code"},
			"subject_types_supported":               []string{"public"},
			"id_token_signing_alg_values_supported": []string{p.signer.Algorithm()},
			"code_challenge_methods_supported":      []string{"S256"},
		})
	case "/jwks":
		jose.ServeJWKS(w, r, jose.JWKS(testkeys.Source(p.signer)))
	case "/token":
		p.token(w, r)
	case "/userinfo":
		p.userinfo(w, r)
	default:
		http.NotFound(w, r)
	}
}

// token redeems a code (RFC 6749 §4.1.3, RFC 7636 §4.6).
func (p *IdP) token(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost || r.ParseForm() != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_request"})
		return
	}
	id, secret, basic := r.BasicAuth()
	if !basic {
		id, secret = r.PostForm.Get("client_id"), r.PostForm.Get("client_secret")
	}
	if id != p.ClientID || secret != ClientSecret {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "invalid_client"})
		return
	}
	code := r.PostForm.Get("code")
	g, ok := decode(code)
	if !ok || r.PostForm.Get("grant_type") != "authorization_code" ||
		(g.RedirectURI != "" && r.PostForm.Get("redirect_uri") != g.RedirectURI) ||
		(g.CodeChallenge != "" && s256(r.PostForm.Get("code_verifier")) != g.CodeChallenge) {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_grant"})
		return
	}
	now := time.Now()
	claims := map[string]any{
		"iss": p.Issuer, "aud": p.ClientID, "sub": g.Subject,
		"iat": now.Add(-time.Second).Unix(), "exp": now.Add(5 * time.Minute).Unix(), "auth_time": now.Unix(),
	}
	for k, v := range map[string]string{"nonce": g.Nonce, "email": g.Email, "preferred_username": g.Username, "name": g.Name} {
		if v != "" {
			claims[k] = v
		}
	}
	if g.EmailVerified {
		claims["email_verified"] = true
	}
	idToken, err := jose.Sign(r.Context(), p.signer, "", claims)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "server_error"})
		return
	}
	// The access token is the code: userinfo reads the identity back from it.
	writeJSON(w, http.StatusOK, map[string]any{"access_token": code, "token_type": "Bearer", "expires_in": 300, "id_token": idToken})
}

func (p *IdP) userinfo(w http.ResponseWriter, r *http.Request) {
	token, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
	g, valid := decode(token)
	if !ok || !valid {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "invalid_token"})
		return
	}
	writeJSON(w, http.StatusOK, g.Identity)
}

func (p *IdP) userInfo(ctx context.Context, client *http.Client) (provider.Identity, error) {
	var id Identity
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, p.Issuer+"/userinfo", nil)
	if err != nil {
		return provider.Identity{}, err
	}
	resp, err := client.Do(req)
	if err != nil {
		return provider.Identity{}, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return provider.Identity{}, fmt.Errorf("userinfo: status %d", resp.StatusCode)
	}
	if err := json.NewDecoder(resp.Body).Decode(&id); err != nil {
		return provider.Identity{}, err
	}
	return provider.Identity{Subject: id.Subject, Email: id.Email, EmailVerified: id.EmailVerified, PreferredUsername: id.Username, DisplayName: id.Name}, nil
}

func s256(verifier string) string {
	sum := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
