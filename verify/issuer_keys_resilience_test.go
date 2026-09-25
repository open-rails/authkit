package verify

import (
	"crypto"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	authkit "github.com/open-rails/authkit"
	"github.com/open-rails/authkit/authtest"
	"github.com/open-rails/authkit/jwtkit"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// jwksProvider serves a peer's JWKS and can be switched to hang (unreachable
// within the attempt timeout), fail with 503, or drop connections.
type jwksProvider struct {
	*httptest.Server
	mode     atomic.Value // "up", "hang", "503", "reset"
	inflight atomic.Int32
	maxConc  atomic.Int32
	hits     atomic.Int32
}

func newJWKSProvider(t *testing.T, signer jwtkit.Signer) *jwksProvider {
	p := &jwksProvider{}
	p.mode.Store("up")
	jwk := jwtkit.PublicToJWK(signer.(jwtkit.PublicKeySigner).PublicKey(), signer.KID(), signer.Algorithm())
	p.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p.hits.Add(1)
		n := p.inflight.Add(1)
		defer p.inflight.Add(-1)
		for {
			m := p.maxConc.Load()
			if n <= m || p.maxConc.CompareAndSwap(m, n) {
				break
			}
		}
		switch p.mode.Load() {
		case "hang":
			<-r.Context().Done()
		case "503":
			w.WriteHeader(http.StatusServiceUnavailable)
		case "reset":
			conn, _, _ := w.(http.Hijacker).Hijack()
			_ = conn.Close()
		default:
			_ = json.NewEncoder(w).Encode(jwtkit.JWKS{Keys: []jwtkit.JWK{jwk}})
		}
	}))
	t.Cleanup(p.Close)
	return p
}

func TestPeerJWKSOutageFailsOnlyPeerTokens(t *testing.T) {
	local := authtest.NewTestIssuer()
	t.Cleanup(local.Close)
	peer := authtest.NewTestIssuerWithAudience(local.Audience())
	t.Cleanup(peer.Close)
	provider := newJWKSProvider(t, peer.Signer())

	v := NewVerifier()
	v.jwksAttemptTimeout, v.jwksBackoffBase, v.jwksBackoffMax = 300*time.Millisecond, 20*time.Millisecond, 100*time.Millisecond
	require.NoError(t, v.AddIssuer(local.URL(), []string{local.Audience()}, IssuerOptions{
		IsLocal: true, RawKeys: map[string]crypto.PublicKey{local.Signer().KID(): local.Signer().(jwtkit.PublicKeySigner).PublicKey()},
	}))
	require.NoError(t, v.AddIssuer(peer.URL(), []string{local.Audience()}, IssuerOptions{JWKSURI: provider.URL, CacheTTL: 100 * time.Millisecond}))

	h := Required(v)(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) }))
	call := func(token string) (int, string, time.Duration) {
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.Header.Set("Authorization", "Bearer "+token)
		rec := httptest.NewRecorder()
		start := time.Now()
		h.ServeHTTP(rec, req)
		var env authkit.ErrorEnvelope
		_ = json.Unmarshal(rec.Body.Bytes(), &env)
		return rec.Code, env.Error.Code, time.Since(start)
	}
	localToken := local.CreateToken("local-user", "local@example.test")
	peerToken := peer.CreateToken("peer-user", "peer@example.test")
	status := func() IssuerKeyStatus {
		sts := v.IssuerKeyStatuses()
		require.Len(t, sts, 1)
		return sts[0]
	}

	// Peer unreachable before its keys were ever fetched: one bounded wait,
	// then 503 issuer_keys_unavailable; later requests fail fast.
	provider.mode.Store("hang")
	code, errCode, took := call(peerToken)
	require.Equal(t, http.StatusServiceUnavailable, code)
	require.Equal(t, string(authkit.CodeIssuerKeysUnavailable), errCode)
	require.Less(t, took, 2*time.Second)
	provider.mode.Store("reset")
	for range 5 {
		code, errCode, took = call(peerToken)
		require.Equal(t, http.StatusServiceUnavailable, code)
		require.Equal(t, string(authkit.CodeIssuerKeysUnavailable), errCode)
		require.Less(t, took, 200*time.Millisecond)
	}
	code, _, _ = call(localToken)
	require.Equal(t, http.StatusOK, code)
	require.Error(t, v.CheckIssuerKeys(t.Context()))
	require.Positive(t, status().Failures)

	// Recovery happens in the background, without request traffic.
	provider.mode.Store("up")
	require.Eventually(t, func() bool { return v.CheckIssuerKeys(t.Context()) == nil }, 5*time.Second, 10*time.Millisecond)
	code, _, _ = call(peerToken)
	require.Equal(t, http.StatusOK, code)
	require.True(t, status().Fresh)

	// Peer down after keys were cached: stale keys keep serving without
	// waiting on the (hanging) refresh, which is single-flighted.
	provider.mode.Store("hang")
	provider.maxConc.Store(0)
	time.Sleep(150 * time.Millisecond) // past CacheTTL
	var wg sync.WaitGroup
	for range 20 {
		wg.Go(func() {
			code, _, took := call(peerToken)
			assert.Equal(t, http.StatusOK, code)
			assert.Less(t, took, 200*time.Millisecond)
		})
	}
	wg.Wait()
	require.Eventually(t, func() bool { return status().Failures > 0 }, 5*time.Second, 10*time.Millisecond)
	require.False(t, status().Fresh)
	require.Error(t, v.CheckIssuerKeys(t.Context()))
	code, _, _ = call(peerToken)
	require.Equal(t, http.StatusOK, code)
	code, _, _ = call(localToken)
	require.Equal(t, http.StatusOK, code)
	require.EqualValues(t, 1, provider.maxConc.Load(), "refresh must be single-flighted")

	provider.mode.Store("503")
	hits := provider.hits.Load()
	time.Sleep(300 * time.Millisecond)
	require.Less(t, provider.hits.Load()-hits, int32(30), "failing refresh must back off")

	provider.mode.Store("up")
	require.Eventually(t, func() bool { return status().Fresh && v.CheckIssuerKeys(t.Context()) == nil }, 5*time.Second, 10*time.Millisecond)
	code, _, _ = call(peerToken)
	require.Equal(t, http.StatusOK, code)
}
