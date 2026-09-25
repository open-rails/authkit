package authprovider

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestOIDCDiscoveryServesStaleAndRecoversInBackground(t *testing.T) {
	var down atomic.Bool
	var hits atomic.Int32
	var srv *httptest.Server
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		if down.Load() {
			w.WriteHeader(http.StatusBadGateway)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"issuer": srv.URL, "authorization_endpoint": srv.URL + "/authorize",
			"token_endpoint": srv.URL + "/token", "jwks_uri": srv.URL + "/jwks",
		})
	}))
	t.Cleanup(srv.Close)

	p := OIDC("idp", srv.URL, "client", "secret").(*oidcProvider)
	p.ttl, p.backoffBase, p.backoffMax = 100*time.Millisecond, 10*time.Millisecond, 50*time.Millisecond
	authURL := func() (string, error) {
		return p.AuthCodeURL(t.Context(), AuthRequest{State: "s", Nonce: "n", RedirectURI: "https://app.example/cb"})
	}

	down.Store(true)
	_, err := authURL()
	require.ErrorIs(t, err, ErrProviderUnavailable)
	require.ErrorIs(t, p.CheckHealth(t.Context()), ErrProviderUnavailable)
	calls := hits.Load()
	_, err = authURL()
	require.ErrorIs(t, err, ErrProviderUnavailable)

	down.Store(false)
	require.Eventually(t, func() bool { return p.CheckHealth(t.Context()) == nil }, 5*time.Second, 10*time.Millisecond)
	require.Greater(t, hits.Load(), calls, "recovery is driven by the background loop")
	u, err := authURL()
	require.NoError(t, err)
	require.Contains(t, u, srv.URL+"/authorize")

	down.Store(true)
	time.Sleep(150 * time.Millisecond) // past the TTL
	for range 10 {
		start := time.Now()
		u, err = authURL()
		require.NoError(t, err)
		require.Contains(t, u, srv.URL+"/authorize")
		require.Less(t, time.Since(start), 100*time.Millisecond)
	}
	require.Eventually(t, func() bool { return errors.Is(p.CheckHealth(t.Context()), ErrProviderUnavailable) }, 5*time.Second, 10*time.Millisecond)

	down.Store(false)
	require.Eventually(t, func() bool { return p.CheckHealth(t.Context()) == nil }, 5*time.Second, 10*time.Millisecond)
}
