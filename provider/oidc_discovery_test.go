package provider

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/open-rails/authkit/internal/cachepolicy"
	"github.com/stretchr/testify/require"
)

func TestOIDCDiscoveryServesStaleAndRecovers(t *testing.T) {
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

	p, clock := clockedOIDC(t, srv.URL)
	authURL := func() (string, error) {
		return p.AuthCodeURL(t.Context(), AuthRequest{State: "s", Nonce: "n", RedirectURI: "https://app.example/cb"})
	}

	down.Store(true)
	_, err := authURL()
	require.ErrorIs(t, err, ErrUnavailable)
	require.ErrorIs(t, p.CheckHealth(t.Context()), ErrUnavailable)

	// The health probe rediscovers, at most once per failure backoff, so it
	// turns healthy without a login.
	start, calls := time.Now(), hits.Load()
	for time.Since(start) < 200*time.Millisecond {
		require.ErrorIs(t, p.CheckHealth(t.Context()), ErrUnavailable)
	}
	require.LessOrEqual(t, hits.Load()-calls, 2*int32(time.Since(start)/(20*time.Millisecond))+2)
	down.Store(false)
	require.Eventually(t, func() bool { return p.CheckHealth(t.Context()) == nil }, 5*time.Second, 10*time.Millisecond)
	calls = hits.Load()
	u, err := authURL()
	require.NoError(t, err)
	require.Contains(t, u, srv.URL+"/authorize")

	require.Equal(t, calls, hits.Load(), "the probe cached discovery")

	// Cached: no rediscovery before RefreshAfter.
	for range 10 {
		_, err = authURL()
		require.NoError(t, err)
	}
	require.Equal(t, calls, hits.Load())

	// Past RefreshAfter with the IdP down, stale metadata serves without
	// waiting on the reload.
	down.Store(true)
	clock.advance(cachepolicy.OIDCDiscovery.RefreshAfter + time.Minute)
	for range 10 {
		start := time.Now()
		u, err = authURL()
		require.NoError(t, err)
		require.Contains(t, u, srv.URL+"/authorize")
		require.Less(t, time.Since(start), 100*time.Millisecond)
	}
	require.Eventually(t, func() bool { return errors.Is(p.CheckHealth(t.Context()), ErrUnavailable) }, 5*time.Second, 10*time.Millisecond)

	down.Store(false)
	require.Eventually(t, func() bool { return p.CheckHealth(t.Context()) == nil }, 5*time.Second, 10*time.Millisecond)
}
