package critical_test

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"testing"

	"github.com/open-rails/authkit"
	"github.com/open-rails/authkit/authtest"
	"github.com/open-rails/authkit/verify"
)

// Every sign-in session is DPoP-bound. Each fixture holds one key: its
// requests carry a fresh proof, so the sessions they open are bound to it,
// and a token bound to a known key goes as DPoP with its proof. Anything
// else (API keys, personal tokens, OAuth tokens) goes as a bearer token.

// dpopKeys are the fixtures' keys by thumbprint.
var dpopKeys sync.Map

func newFixtureKey(t *testing.T) *authtest.DPoPKey {
	key := authtest.NewDPoPKey(t)
	dpopKeys.Store(key.Thumbprint(), key)
	return key
}

// bound reports a token bound to a DPoP key (cnf.jkt), whoever holds it.
func bound(token string) bool {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return false
	}
	raw, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return false
	}
	var claims struct {
		Cnf struct {
			JKT string `json:"jkt"`
		} `json:"cnf"`
	}
	return json.Unmarshal(raw, &claims) == nil && claims.Cnf.JKT != ""
}

// boundKey is the fixture key token is bound to (its cnf.jkt), and the
// origin of its issuer, which a proof's htu names.
func boundKey(token string) (*authtest.DPoPKey, string) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, ""
	}
	raw, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, ""
	}
	var claims struct {
		Issuer string `json:"iss"`
		Cnf    struct {
			JKT string `json:"jkt"`
		} `json:"cnf"`
	}
	if json.Unmarshal(raw, &claims) != nil || claims.Cnf.JKT == "" {
		return nil, ""
	}
	key, ok := dpopKeys.Load(claims.Cnf.JKT)
	if !ok {
		return nil, ""
	}
	return key.(*authtest.DPoPKey), origin(claims.Issuer)
}

func origin(raw string) string {
	u, err := url.Parse(raw)
	if err != nil {
		return ""
	}
	return u.Scheme + "://" + u.Host
}

// authorize sets r's credential: DPoP with a proof for a token bound to a
// fixture key, else Bearer.
func authorize(t testing.TB, r *http.Request, credential string) {
	t.Helper()
	if key, iss := boundKey(credential); key != nil {
		r.Header.Set("Authorization", "DPoP "+credential)
		r.Header.Set("DPoP", key.Proof(t, r.Method, iss+r.URL.EscapedPath(), credential, ""))
		return
	}
	r.Header.Set("Authorization", "Bearer "+credential)
}

// verifyToken is c's verification of token as a request presents it: a
// DPoP-bound token with its proof, as Client.Verify, which takes no request,
// cannot check.
func verifyToken(t testing.TB, c *authkit.Client, token string) (verify.Claims, error) {
	t.Helper()
	r, err := http.NewRequestWithContext(context.Background(), http.MethodGet, "http://verify.invalid/verify", nil)
	if err != nil {
		return verify.Claims{}, err
	}
	authorize(t, r, token)
	return c.VerifyRequest(r)
}

// prove adds a proof of f's key to a request presenting no bound token: a
// sign-in, a refresh or a bearer credential, at the issuer's origin.
func (f *fixture) prove(t testing.TB, r *http.Request) {
	t.Helper()
	r.Header.Set("DPoP", f.dpop.Proof(t, r.Method, origin(f.cfg.Issuer)+r.URL.EscapedPath(), "", ""))
}

// The refresh token travels only in its HttpOnly cookie. The fixture keeps
// tests' view of it: a sign-in's cookie is copied into the answer's
// token_set.refresh_token, and a refresh_token in a /token body goes back as
// the cookie.

const refreshCookieMark = "authkit_rt"

// refreshFromCookie copies a response's refresh cookie into its token set.
func (f *fixture) refreshFromCookie(header http.Header, body []byte) []byte {
	var value string
	for _, c := range (&http.Response{Header: header}).Cookies() {
		if strings.Contains(c.Name, refreshCookieMark) && c.Value != "" && c.MaxAge >= 0 {
			f.mu.Lock()
			f.refreshCookie = c.Name
			f.mu.Unlock()
			value = c.Value
		}
	}
	if value == "" {
		return body
	}
	var doc map[string]any
	if json.Unmarshal(body, &doc) != nil {
		return body
	}
	tokens, ok := doc["token_set"].(map[string]any)
	if !ok {
		return body
	}
	tokens["refresh_token"] = value
	out, err := json.Marshal(doc)
	if err != nil {
		return body
	}
	return out
}

// refreshToCookie moves a /token body's refresh_token into its cookie.
func (f *fixture) refreshToCookie(r *http.Request, path string, body any) any {
	m, ok := body.(map[string]string)
	if !ok || path != "/token" || m["refresh_token"] == "" {
		return body
	}
	f.mu.Lock()
	name := f.refreshCookie
	f.mu.Unlock()
	if name == "" {
		return body
	}
	moved := map[string]string{}
	for k, v := range m {
		if k != "refresh_token" {
			moved[k] = v
		}
	}
	r.AddCookie(&http.Cookie{Name: name, Value: m["refresh_token"]})
	return moved
}

// credentialTransport presents credential on every request, as authorize
// does: a client handing a session token to code calling over HTTP.
type credentialTransport struct {
	t          testing.TB
	credential string
	base       http.RoundTripper
}

func (c credentialTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	r = r.Clone(r.Context())
	authorize(c.t, r, c.credential)
	return c.base.RoundTrip(r)
}
