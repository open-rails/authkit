package authprovider

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	jwt "github.com/golang-jwt/jwt/v5"
	"github.com/open-rails/authkit/jwtkit"
	"github.com/stretchr/testify/require"
)

type idpKey struct {
	kid string
	key *rsa.PrivateKey
}

// keyIdP is an OpenID Provider whose published keys, ID-token signing key and
// availability the test controls.
type keyIdP struct {
	srv       *httptest.Server
	down      atomic.Bool
	mu        sync.Mutex
	published []idpKey
	signing   idpKey
	nonce     string
}

func newKeyIdP(t *testing.T) *keyIdP {
	f := &keyIdP{}
	f.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if f.down.Load() {
			w.WriteHeader(http.StatusBadGateway)
			return
		}
		f.mu.Lock()
		defer f.mu.Unlock()
		switch r.URL.Path {
		case "/.well-known/openid-configuration":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"issuer": f.srv.URL, "authorization_endpoint": f.srv.URL + "/authorize",
				"token_endpoint": f.srv.URL + "/token", "jwks_uri": f.srv.URL + "/jwks",
			})
		case "/jwks":
			var ks jwtkit.JWKS
			for _, k := range f.published {
				ks.Keys = append(ks.Keys, jwtkit.PublicToJWK(&k.key.PublicKey, k.kid, "RS256"))
			}
			_ = json.NewEncoder(w).Encode(ks)
		case "/token":
			now := time.Now()
			tok := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{
				"iss": f.srv.URL, "aud": "client", "sub": "subject", "nonce": f.nonce,
				"iat": now.Unix(), "exp": now.Add(5 * time.Minute).Unix(),
			})
			tok.Header["kid"] = f.signing.kid
			signed, _ := tok.SignedString(f.signing.key)
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{"access_token": "at", "token_type": "Bearer", "id_token": signed})
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(f.srv.Close)
	return f
}

func newIdPKey(t *testing.T, kid string) idpKey {
	k, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	return idpKey{kid: kid, key: k}
}

func (f *keyIdP) set(signing idpKey, published ...idpKey) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.signing, f.published = signing, published
}

func clockedOIDC(t *testing.T, issuer string) (*oidcProvider, *atomic.Int64) {
	var offset atomic.Int64
	p := OIDC("idp", issuer, "client", "secret").(*oidcProvider)
	p.now = func() time.Time { return time.Now().Add(time.Duration(offset.Load())) }
	p.backoffBase, p.backoffMax = 10*time.Millisecond, 50*time.Millisecond
	return p, &offset
}

// A key the IdP stops publishing stops verifying once discovery refreshes: the
// key set is rebuilt with every successful rediscovery.
func TestOIDCRediscoveryDropsRevokedKeys(t *testing.T) {
	idp := newKeyIdP(t)
	a, b := newIdPKey(t, "a"), newIdPKey(t, "b")
	idp.set(a, a)
	p, offset := clockedOIDC(t, idp.srv.URL)
	exchange := func() error {
		_, err := p.Exchange(t.Context(), ExchangeRequest{Code: "code", RedirectURI: "https://app.example/cb"})
		return err
	}
	require.NoError(t, exchange())

	idp.set(a, b) // a is revoked, but still signs (compromised)
	offset.Add(int64(2 * time.Hour))
	mark := p.now()
	_, err := p.AuthCodeURL(t.Context(), AuthRequest{RedirectURI: "https://app.example/cb"})
	require.NoError(t, err)
	require.Eventually(t, func() bool {
		p.mu.Lock()
		defer p.mu.Unlock()
		return !p.disc.fetchedAt.Before(mark)
	}, 5*time.Second, 5*time.Millisecond)
	require.Error(t, exchange(), "revoked key must not verify after rediscovery")

	idp.set(b, b)
	require.NoError(t, exchange())
}

// Stale discovery serves logins up to MaxStale (4h default) after the last
// successful discovery; past it the provider fails closed until it recovers.
func TestOIDCDiscoveryMaxStale(t *testing.T) {
	idp := newKeyIdP(t)
	a := newIdPKey(t, "a")
	idp.set(a, a)
	p, offset := clockedOIDC(t, idp.srv.URL)
	authURL := func() error {
		_, err := p.AuthCodeURL(t.Context(), AuthRequest{RedirectURI: "https://app.example/cb"})
		return err
	}
	require.NoError(t, authURL())

	idp.down.Store(true)
	offset.Add(int64(3 * time.Hour)) // past the 1h TTL, inside MaxStale
	require.NoError(t, authURL())
	require.Eventually(t, func() bool { return p.CheckHealth(t.Context()) != nil }, 5*time.Second, 5*time.Millisecond)
	require.NoError(t, authURL())

	offset.Add(int64(2 * time.Hour)) // 5h since the last success
	require.ErrorIs(t, authURL(), ErrProviderUnavailable)
	require.ErrorIs(t, p.CheckHealth(t.Context()), ErrProviderUnavailable)

	idp.down.Store(false)
	require.Eventually(t, func() bool { return authURL() == nil }, 5*time.Second, 10*time.Millisecond)
	require.NoError(t, p.CheckHealth(t.Context()))
}
