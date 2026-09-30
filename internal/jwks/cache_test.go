package jwks

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/open-rails/authkit/internal/testkeys"
	"github.com/open-rails/authkit/keys"
	"github.com/stretchr/testify/require"
)

// A slower, older fetch can never overwrite the keys a newer fetch installed.
func TestOlderFetchCannotOverwriteNewer(t *testing.T) {
	a, b := testkeys.RSA("a"), testkeys.RSA("b")
	jwk := func(s keys.Signer) keys.JWKS {
		return keys.JWKS{Keys: []keys.JWK{keys.PublicJWK(s.Public(), s.KID(), "")}}
	}
	release := make(chan struct{})
	var n atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if n.Add(1) == 1 {
			<-release
			_ = json.NewEncoder(w).Encode(jwk(a))
			return
		}
		_ = json.NewEncoder(w).Encode(jwk(b))
	}))
	t.Cleanup(srv.Close)
	c := New(nil)
	c.AttemptTimeout = 5 * time.Second
	c.mu.Lock()
	e := c.entryLocked(Issuer{Issuer: "https://peer.example", URL: srv.URL})
	c.mu.Unlock()
	older := make(chan error, 1)
	go func() { older <- c.fetch(context.Background(), e) }()
	require.Eventually(t, func() bool { return n.Load() == 1 }, 5*time.Second, time.Millisecond)
	require.NoError(t, c.fetch(context.Background(), e))
	close(release)
	<-older
	c.mu.RLock()
	defer c.mu.RUnlock()
	require.NotContains(t, e.keys, "a")
	require.Contains(t, e.keys, "b")
}
