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

	// The next login after the failure backoff recovers it.
	down.Store(false)
	require.Eventually(t, func() bool { _, err := authURL(); return err == nil }, 5*time.Second, 10*time.Millisecond)
	require.NoError(t, p.CheckHealth(t.Context()))
	u, err := authURL()
	require.NoError(t, err)
	require.Contains(t, u, srv.URL+"/authorize")

	// Cached: no rediscovery before RefreshAfter.
	calls := hits.Load()
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
	require.Eventually(t, func() bool { _, _ = authURL(); return p.CheckHealth(t.Context()) == nil }, 5*time.Second, 10*time.Millisecond)
}
