package verify

import (
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/open-rails/authkit/iam"
	"github.com/open-rails/authkit/internal/jose"
	"github.com/open-rails/authkit/internal/testdb"
	"github.com/open-rails/authkit/internal/testdpop"
	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/require"
)

// TestDPoPProofIsSpentOnce: instances of a resource server behind one public
// URL refuse a replayed proof. Without Redis an instance refuses it itself;
// instances sharing a Redis refuse it whichever one it reaches; while that
// Redis is down, each instance still refuses its own replays, promptly.
func TestDPoPProofIsSpentOnce(t *testing.T) {
	const base = "https://api.example"
	target := base + "/v1/things"
	peer := newFixture(t).peer
	key := testdpop.Key(t)
	bound := sign(t, peer, jose.ResourceAccessTokenType, peerIssuer, map[string]any{
		"sub": "user-1", "client_id": "console", "cnf": map[string]any{"jkt": testdpop.Thumbprint(t, key)},
	})
	instance := func(rdb redis.UniversalClient) func(proof string) int {
		v := NewVerifier(WithDPoP(rdb), WithPublicURL(base))
		require.NoError(t, v.AddIssuer(peerIssuer, []string{audience}, IssuerOptions{Keys: []iam.RemoteApplicationKey{pemKey(t, peer)}}))
		h := Required(v)(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) }))
		return func(proof string) int {
			r := httptest.NewRequest(http.MethodGet, target, nil)
			r.Header.Set("Authorization", "DPoP "+bound)
			r.Header.Set("DPoP", proof)
			w := httptest.NewRecorder()
			h.ServeHTTP(w, r)
			return w.Code
		}
	}
	proof := func() string { return testdpop.Proof(t, key, http.MethodGet, target, bound, nil) }

	t.Run("one instance without Redis", func(t *testing.T) {
		a := instance(nil)
		p := proof()
		require.Equal(t, http.StatusOK, a(p))
		require.Equal(t, http.StatusUnauthorized, a(p), "the replay was admitted")
	})

	t.Run("two instances sharing a Redis", func(t *testing.T) {
		rdb := testdb.ScratchRedis(t)
		a, b := instance(rdb), instance(rdb)
		p := proof()
		require.Equal(t, http.StatusOK, a(p))
		require.Equal(t, http.StatusUnauthorized, b(p), "the other instance admitted the replay")
		require.Equal(t, http.StatusUnauthorized, a(p))
		require.Equal(t, http.StatusOK, b(proof()), "a fresh proof")
	})

	t.Run("each instance while Redis is down", func(t *testing.T) {
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		require.NoError(t, err)
		addr := ln.Addr().String()
		require.NoError(t, ln.Close())
		down := redis.NewClient(&redis.Options{Addr: addr, MaxRetries: -1})
		t.Cleanup(func() { _ = down.Close() })
		a := instance(down)
		started := time.Now()
		p := proof()
		require.Equal(t, http.StatusOK, a(p))
		require.Equal(t, http.StatusUnauthorized, a(p), "an outage admitted the replay")
		require.Less(t, time.Since(started), 2*time.Second)
	})
}
