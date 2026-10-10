package verify

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/golang-jwt/jwt/v5"
	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/require"

	"github.com/open-rails/authkit/iam"
	"github.com/open-rails/authkit/internal/jose"
	"github.com/open-rails/authkit/internal/testdb"
	"github.com/open-rails/authkit/internal/testdpop"
)

// TestStoredDPoPNonces: a resource server's nonces (RFC 9449 §9) need no
// configured key. A proof without a current one is refused 401
// use_dpop_nonce with a fresh DPoP-Nonce; instances sharing a Redis accept
// each other's nonces, and a nonce no store issued is refused.
func TestStoredDPoPNonces(t *testing.T) {
	const base = "https://api.example"
	target := base + "/v1/things"
	peer := newFixture(t).peer
	key := testdpop.Key(t)
	bound := sign(t, peer, jose.ResourceAccessTokenType, peerIssuer, map[string]any{
		"sub": "user-1", "client_id": "console", "cnf": map[string]any{"jkt": testdpop.Thumbprint(t, key)},
	})
	instance := func(rdb redis.UniversalClient) func(nonce string) (int, string) {
		v := NewVerifier(WithDPoP(rdb), WithStoredDPoPNonces(), WithPublicURL(base))
		require.NoError(t, v.AddIssuer(peerIssuer, []string{audience}, IssuerOptions{Keys: []iam.RemoteApplicationKey{pemKey(t, peer)}}))
		h := Required(v)(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) }))
		return func(nonce string) (int, string) {
			r := httptest.NewRequest(http.MethodGet, target, nil)
			r.Header.Set("Authorization", "DPoP "+bound)
			r.Header.Set("DPoP", testdpop.Proof(t, key, http.MethodGet, target, bound, func(tok *jwt.Token) {
				if nonce != "" {
					tok.Claims.(jwt.MapClaims)["nonce"] = nonce
				}
			}))
			w := httptest.NewRecorder()
			h.ServeHTTP(w, r)
			return w.Code, w.Header().Get("DPoP-Nonce")
		}
	}

	t.Run("one instance without Redis", func(t *testing.T) {
		a := instance(nil)
		code, nonce := a("")
		require.Equal(t, http.StatusUnauthorized, code)
		require.NotEmpty(t, nonce)
		code, _ = a(nonce)
		require.Equal(t, http.StatusOK, code)
		code, _ = a("AAAAAAAAAAAAAAAAAAAAAA")
		require.Equal(t, http.StatusUnauthorized, code, "a nonce it never issued")
	})

	t.Run("two instances sharing a Redis", func(t *testing.T) {
		rdb := testdb.ScratchRedis(t)
		a, b := instance(rdb), instance(rdb)
		_, nonce := a("")
		code, _ := b(nonce)
		require.Equal(t, http.StatusOK, code, "the other instance refused a shared nonce")
	})
}

// TestPublicHosts: a proof names the URL the client used. A host the
// WithPublicHosts hook vouches for stands in for WithPublicURL's host; any
// other Host header changes nothing.
func TestPublicHosts(t *testing.T) {
	peer := newFixture(t).peer
	key := testdpop.Key(t)
	bound := sign(t, peer, jose.ResourceAccessTokenType, peerIssuer, map[string]any{
		"sub": "user-1", "client_id": "console", "cnf": map[string]any{"jkt": testdpop.Thumbprint(t, key)},
	})
	v := NewVerifier(WithDPoP(nil), WithPublicURL("https://api.example"), WithPublicHosts(func(_ context.Context, host string) (bool, error) {
		return host == "shop.api.example", nil
	}))
	require.NoError(t, v.AddIssuer(peerIssuer, []string{audience}, IssuerOptions{Keys: []iam.RemoteApplicationKey{pemKey(t, peer)}}))
	h := Required(v)(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) }))
	call := func(host, htu string) int {
		r := httptest.NewRequest(http.MethodGet, "https://"+host+"/v1/things", nil)
		r.Header.Set("Authorization", "DPoP "+bound)
		r.Header.Set("DPoP", testdpop.Proof(t, key, http.MethodGet, htu, bound, nil))
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		return w.Code
	}
	require.Equal(t, http.StatusOK, call("api.example", "https://api.example/v1/things"))
	require.Equal(t, http.StatusOK, call("shop.api.example", "https://shop.api.example/v1/things"))
	require.Equal(t, http.StatusUnauthorized, call("evil.example", "https://evil.example/v1/things"), "an unvouched Host")
	require.Equal(t, http.StatusOK, call("evil.example", "https://api.example/v1/things"), "an unvouched Host falls back to the public URL")
}
