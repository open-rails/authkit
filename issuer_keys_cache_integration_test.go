package authkit_test

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

	"github.com/go-jose/go-jose/v4"
	jwt "github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/stretchr/testify/require"

	hauth "github.com/open-rails/authkit/auth"
	"github.com/open-rails/authkit/iam"
)

// rotatingIssuer is a trusted issuer whose published keys the test swaps,
// counting JWKS fetches.
type rotatingIssuer struct {
	url  string
	hits atomic.Int32
	mu   sync.Mutex
	keys map[string]*rsa.PrivateKey
}

func newRotatingIssuer(t *testing.T) *rotatingIssuer {
	t.Helper()
	f := &rotatingIssuer{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		f.hits.Add(1)
		f.mu.Lock()
		defer f.mu.Unlock()
		var set jose.JSONWebKeySet
		for kid, k := range f.keys {
			set.Keys = append(set.Keys, jose.JSONWebKey{Key: &k.PublicKey, KeyID: kid, Algorithm: "RS256", Use: "sig"})
		}
		_ = json.NewEncoder(w).Encode(set)
	}))
	t.Cleanup(srv.Close)
	f.url = srv.URL
	return f
}

func (f *rotatingIssuer) publish(keys map[string]*rsa.PrivateKey) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.keys = keys
}

func (f *rotatingIssuer) token(t *testing.T, kid string, key *rsa.PrivateKey) string {
	t.Helper()
	now := time.Now()
	tok := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{"iss": f.url, "aud": oauthResource, "sub": "u-1", "client_id": "shop-console",
		"scope": "api:merchant", "iat": now.Unix(), "exp": now.Add(5 * time.Minute).Unix(), "jti": uuid.NewString()})
	tok.Header["typ"], tok.Header["kid"] = "at+jwt", kid
	s, err := tok.SignedString(key)
	require.NoError(t, err)
	return s
}

func rsaKey(t *testing.T) *rsa.PrivateKey {
	t.Helper()
	k, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	return k
}

// A remote application's JWKS is read through the shared cache: fetched once,
// refetched when a token names a new kid; the registry row itself stays live,
// so disabling the application stops its tokens on the next request.
func TestResourceServerIssuerKeysCachedLiveRegistry(t *testing.T) {
	ctx := t.Context()
	f := newRotatingIssuer(t)
	k1, k2 := rsaKey(t), rsaKey(t)
	f.publish(map[string]*rsa.PrivateKey{"k1": k1})
	d := newResourceDeployment(t)
	app := iam.RemoteApplication{Issuer: f.url, JWKSURI: f.url + "/keys", Enabled: true, Role: d.operator}
	require.NoError(t, d.auth.DeclareRemoteApplications(ctx, d.a, []iam.RemoteApplication{app}))
	a := d.auth.Authenticator()
	authenticate := func(token string) error {
		r := httptest.NewRequest(http.MethodGet, oauthResource+"/v1/things", nil)
		r.Header.Set("Authorization", "Bearer "+token)
		_, err := a.Authenticate(r)
		return err
	}

	for range 10 {
		require.NoError(t, authenticate(f.token(t, "k1", k1)))
	}
	require.EqualValues(t, 1, f.hits.Load(), "keys are cached")

	f.publish(map[string]*rsa.PrivateKey{"k1": k1, "k2": k2})
	require.NoError(t, authenticate(f.token(t, "k2", k2)), "a rotated-in kid refetches at once")
	require.EqualValues(t, 2, f.hits.Load())
	require.ErrorIs(t, authenticate(f.token(t, "k3", rsaKey(t))), hauth.ErrUnauthenticated)
	require.EqualValues(t, 2, f.hits.Load(), "unknown kids refetch at most every 30 seconds")

	app.Enabled = false
	require.NoError(t, d.auth.DeclareRemoteApplications(ctx, d.a, []iam.RemoteApplication{app}))
	require.ErrorIs(t, authenticate(f.token(t, "k1", k1)), hauth.ErrUnauthenticated, "a disabled application's tokens stop on the next request")
}
