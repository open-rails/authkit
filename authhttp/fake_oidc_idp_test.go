package authhttp

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	jwt "github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/require"

	"github.com/open-rails/authkit/authprovider"
	"github.com/open-rails/authkit/jwtkit"
)

// fakeOIDCIdP is a minimal OpenID Provider (discovery, JWKS, token endpoint)
// that the real OIDC browser routes can complete a login against. The test sets
// the id_token claims (sub/email/email_verified) and the nonce echoed from the
// authorize URL before driving the callback.
type fakeOIDCIdP struct {
	Server   *httptest.Server
	ClientID string

	key *rsa.PrivateKey
	kid string

	mu            sync.Mutex
	nonce         string
	codeChallenge string
	claims        map[string]any
}

func newFakeOIDCIdP(t *testing.T, clientID string) *fakeOIDCIdP {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	f := &fakeOIDCIdP{ClientID: clientID, key: key, kid: "idp-" + uniqueSuffix(), claims: map[string]any{}}
	f.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/.well-known/openid-configuration":
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{
				"issuer":                                f.Server.URL,
				"authorization_endpoint":                f.Server.URL + "/authorize",
				"token_endpoint":                        f.Server.URL + "/token",
				"jwks_uri":                              f.Server.URL + "/jwks",
				"response_types_supported":              []string{"code"},
				"subject_types_supported":               []string{"public"},
				"id_token_signing_alg_values_supported": []string{"RS256"},
			})
		case "/jwks":
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(jwtkit.JWKS{Keys: []jwtkit.JWK{jwtkit.PublicToJWK(&f.key.PublicKey, f.kid, "RS256")}})
		case "/token":
			if r.Method != http.MethodPost {
				http.Error(w, "method", http.StatusMethodNotAllowed)
				return
			}
			if want := f.expectedCodeChallenge(); want != "" {
				sum := sha256.Sum256([]byte(r.FormValue("code_verifier")))
				if base64.RawURLEncoding.EncodeToString(sum[:]) != want {
					http.Error(w, `{"error":"invalid_grant"}`, http.StatusBadRequest)
					return
				}
			}
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{
				"access_token": "idp-access-token",
				"token_type":   "Bearer",
				"id_token":     f.idToken(t),
			})
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(f.Server.Close)
	return f
}

// SetIdentity fixes the claims the next id_token carries.
func (f *fakeOIDCIdP) SetIdentity(subject, email string, emailVerified bool, extra map[string]any) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.claims = map[string]any{"sub": subject, "email": email, "email_verified": emailVerified}
	for k, v := range extra {
		f.claims[k] = v
	}
}

// SetNonce records the nonce from the authorize URL so the id_token echoes it.
// ExpectCodeChallenge makes the token endpoint enforce PKCE (S256) against the
// code_challenge the authorize request carried; "" disables the check.
func (f *fakeOIDCIdP) ExpectCodeChallenge(challenge string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.codeChallenge = challenge
}

func (f *fakeOIDCIdP) expectedCodeChallenge() string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.codeChallenge
}

func (f *fakeOIDCIdP) SetNonce(nonce string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.nonce = nonce
}

func (f *fakeOIDCIdP) idToken(t *testing.T) string {
	f.mu.Lock()
	defer f.mu.Unlock()
	now := time.Now()
	claims := jwt.MapClaims{
		"iss":   f.Server.URL,
		"aud":   f.ClientID,
		"iat":   now.Add(-time.Second).Unix(),
		"exp":   now.Add(5 * time.Minute).Unix(),
		"nonce": f.nonce,
	}
	for k, v := range f.claims {
		claims[k] = v
	}
	tok := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	tok.Header["kid"] = f.kid
	signed, err := tok.SignedString(f.key)
	require.NoError(t, err)
	return signed
}

// Provider returns an OIDC provider pointing at this IdP.
func (f *fakeOIDCIdP) Provider(name string, opts ...authprovider.Option) authprovider.Provider {
	return authprovider.OIDC(name, f.Server.URL, f.ClientID, "idp-secret", opts...)
}
