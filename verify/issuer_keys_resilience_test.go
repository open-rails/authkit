package verify

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/open-rails/authkit/iam"
	"github.com/open-rails/authkit/internal/cachepolicy"
	"github.com/open-rails/authkit/internal/errmodel"
	"github.com/open-rails/authkit/internal/jose"
	"github.com/open-rails/authkit/internal/jwks"
	"github.com/open-rails/authkit/internal/testkeys"
	"github.com/open-rails/authkit/keys"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const testAudience = "test-app"

// testClock is real time moved by offset.
type testClock struct{ offset atomic.Int64 }

func (c *testClock) Now() time.Time          { return time.Now().Add(time.Duration(c.offset.Load())) }
func (c *testClock) advance(d time.Duration) { c.offset.Add(int64(d)) }

// testKeysVerifier is a Verifier whose issuer-key cache runs the production
// policy on clock, with a short load timeout and failure backoff.
func testKeysVerifier(clock *testClock, loadTimeout, backoff time.Duration) *Verifier {
	o := cachepolicy.IssuerKeys
	o.Clock, o.LoadTimeout, o.FailureBackoff = clock, loadTimeout, backoff
	v := NewVerifier()
	v.keys = jwks.New(nil, o)
	return v
}

// testIssuer is an issuer URL and the key its tokens are signed with.
type testIssuer struct {
	url    string
	signer keys.Signer
}

func newTestIssuer(t *testing.T, url string) testIssuer {
	t.Helper()
	return testIssuer{url: url, signer: testkeys.RSA(url)}
}

func (i testIssuer) token(t *testing.T, sub string) string {
	t.Helper()
	now := time.Now()
	token, err := jose.Sign(context.Background(), i.signer, jose.AccessTokenType, map[string]any{
		"sub": sub, "iss": i.url, "aud": testAudience, "iat": now.Unix(), "exp": now.Add(time.Hour).Unix(),
	})
	require.NoError(t, err)
	return token
}

// jwksProvider serves a peer's JWKS and can be switched to hang (unreachable
// within the attempt timeout), fail with 503, or drop connections.
type jwksProvider struct {
	*httptest.Server
	mode     atomic.Value // "up", "hang", "503", "reset"
	inflight atomic.Int32
	maxConc  atomic.Int32
	hits     atomic.Int32
}

func newJWKSProvider(t *testing.T, signer keys.Signer) *jwksProvider {
	p := &jwksProvider{}
	p.mode.Store("up")
	jwk := keys.PublicJWK(signer.Public(), signer.KID(), signer.Algorithm())
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
			_ = json.NewEncoder(w).Encode(keys.JWKS{Keys: []keys.JWK{jwk}})
		}
	}))
	t.Cleanup(p.Close)
	return p
}

func TestPeerJWKSOutageFailsOnlyPeerTokens(t *testing.T) {
	local, peer := newTestIssuer(t, "https://local.example"), newTestIssuer(t, "https://peer.example")
	provider := newJWKSProvider(t, peer.signer)

	clock := &testClock{}
	v := testKeysVerifier(clock, 300*time.Millisecond, 200*time.Millisecond)
	require.NoError(t, v.AddIssuer(local.url, []string{testAudience}, IssuerOptions{
		IsLocal: true, KeySource: testkeys.Source(local.signer),
	}))
	require.NoError(t, v.AddIssuer(peer.url, []string{testAudience}, IssuerOptions{JWKSURI: provider.URL}))

	h := Required(v)(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) }))
	call := func(token string) (int, string, time.Duration) {
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.Header.Set("Authorization", "Bearer "+token)
		rec := httptest.NewRecorder()
		start := time.Now()
		h.ServeHTTP(rec, req)
		var env iam.ErrorEnvelope
		_ = json.Unmarshal(rec.Body.Bytes(), &env)
		return rec.Code, env.Error.Code, time.Since(start)
	}
	localToken := local.token(t, "local-user")
	peerToken := peer.token(t, "peer-user")
	status := func() IssuerKeyStatus {
		sts := v.IssuerKeyStatuses()
		require.Len(t, sts, 1)
		return sts[0]
	}

	// Peer unreachable before its keys were ever fetched: one bounded wait,
	// then 503 issuer_keys_unavailable; within the failure backoff later
	// requests fail fast without refetching.
	provider.mode.Store("hang")
	code, errCode, took := call(peerToken)
	require.Equal(t, http.StatusServiceUnavailable, code)
	require.Equal(t, string(errmodel.CodeIssuerKeysUnavailable), errCode)
	require.Less(t, took, 2*time.Second)
	provider.mode.Store("reset")
	hits := provider.hits.Load()
	for range 5 {
		code, errCode, took = call(peerToken)
		require.Equal(t, http.StatusServiceUnavailable, code)
		require.Equal(t, string(errmodel.CodeIssuerKeysUnavailable), errCode)
		require.Less(t, took, 200*time.Millisecond)
	}
	require.LessOrEqual(t, provider.hits.Load()-hits, int32(1), "an absent issuer's failed fetch must back off")
	code, _, _ = call(localToken)
	require.Equal(t, http.StatusOK, code)
	require.Error(t, v.CheckIssuerKeys(t.Context()))
	require.Positive(t, status().Failures)

	// The next token naming the peer after the backoff recovers it.
	provider.mode.Store("up")
	require.Eventually(t, func() bool { code, _, _ := call(peerToken); return code == http.StatusOK }, 5*time.Second, 10*time.Millisecond)
	require.NoError(t, v.CheckIssuerKeys(t.Context()))
	require.True(t, status().Fresh)

	// Reads are cached: no fetch until the keys are due for refresh.
	hits = provider.hits.Load()
	for range 20 {
		code, _, _ = call(peerToken)
		require.Equal(t, http.StatusOK, code)
	}
	require.Equal(t, hits, provider.hits.Load())

	// Peer down after keys were cached: stale keys keep serving without
	// waiting on the (hanging) refresh, which is single-flighted.
	provider.mode.Store("hang")
	provider.maxConc.Store(0)
	clock.advance(cachepolicy.IssuerKeys.RefreshAfter + time.Minute)
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

	// A failing refresh backs off however many tokens arrive.
	provider.mode.Store("503")
	hits = provider.hits.Load()
	for deadline := time.Now().Add(300 * time.Millisecond); time.Now().Before(deadline); {
		code, _, _ = call(peerToken)
		require.Equal(t, http.StatusOK, code)
	}
	require.Less(t, provider.hits.Load()-hits, int32(30), "failing refresh must back off")

	provider.mode.Store("up")
	require.Eventually(t, func() bool {
		call(peerToken)
		return status().Fresh && v.CheckIssuerKeys(t.Context()) == nil
	}, 5*time.Second, 10*time.Millisecond)
}

// Stale peer keys verify only up to MaxStale after the last successful fetch;
// past it the peer fails closed (so blocking our refetch cannot keep a revoked
// key valid) and recovers on the next successful refetch.
func TestPeerJWKSStaleKeysCappedAtMaxStale(t *testing.T) {
	local, peer := newTestIssuer(t, "https://local.example"), newTestIssuer(t, "https://peer.example")
	provider := newJWKSProvider(t, peer.signer)

	clock := &testClock{}
	v := testKeysVerifier(clock, 300*time.Millisecond, 20*time.Millisecond)
	require.NoError(t, v.AddIssuer(local.url, []string{testAudience}, IssuerOptions{
		IsLocal: true, KeySource: testkeys.Source(local.signer),
	}))
	require.NoError(t, v.AddIssuer(peer.url, []string{testAudience}, IssuerOptions{JWKSURI: provider.URL}))

	h := Required(v)(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) }))
	call := func(token string) (int, string) {
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.Header.Set("Authorization", "Bearer "+token)
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		var env iam.ErrorEnvelope
		_ = json.Unmarshal(rec.Body.Bytes(), &env)
		return rec.Code, env.Error.Code
	}
	localToken := local.token(t, "local-user")
	peerToken := peer.token(t, "peer-user")
	status := func() IssuerKeyStatus { return v.IssuerKeyStatuses()[0] }
	maxStale := cachepolicy.IssuerKeys.MaxStale

	code, _ := call(peerToken)
	require.Equal(t, http.StatusOK, code)
	require.Equal(t, maxStale, status().MaxStale)

	provider.mode.Store("503")
	clock.advance(maxStale - time.Hour) // past RefreshAfter, inside MaxStale
	code, _ = call(peerToken)
	require.Equal(t, http.StatusOK, code)
	require.Eventually(t, func() bool { return status().Failures > 0 }, 5*time.Second, 10*time.Millisecond)
	st := status()
	require.False(t, st.Expired)
	require.GreaterOrEqual(t, st.Age, maxStale-time.Hour)
	require.ErrorContains(t, v.CheckIssuerKeys(t.Context()), "stale")
	code, _ = call(peerToken)
	require.Equal(t, http.StatusOK, code)

	clock.advance(time.Hour + time.Minute) // past MaxStale
	code, errCode := call(peerToken)
	require.Equal(t, http.StatusServiceUnavailable, code)
	require.Equal(t, string(errmodel.CodeIssuerKeysUnavailable), errCode)
	code, _ = call(localToken)
	require.Equal(t, http.StatusOK, code)
	require.True(t, status().Expired)
	require.ErrorContains(t, v.CheckIssuerKeys(t.Context()), "failing closed")

	provider.mode.Store("up")
	require.Eventually(t, func() bool { code, _ := call(peerToken); return code == http.StatusOK }, 5*time.Second, 10*time.Millisecond)
	require.NoError(t, v.CheckIssuerKeys(t.Context()))
	st = status()
	require.False(t, st.Expired)
	require.Less(t, st.Age, time.Minute)
}

// CheckIssuerKeys retries a failing issuer through the key cache, at most once
// per failure backoff, so it turns healthy once the issuer recovers without
// any token naming it.
func TestPeerJWKSHealthProbeRecovers(t *testing.T) {
	peer := newTestIssuer(t, "https://peer.example")
	provider := newJWKSProvider(t, peer.signer)
	clock := &testClock{}
	backoff := 50 * time.Millisecond
	v := testKeysVerifier(clock, 300*time.Millisecond, backoff)
	require.NoError(t, v.AddIssuer(peer.url, []string{testAudience}, IssuerOptions{JWKSURI: provider.URL}))
	verify := func() error {
		_, err := v.Verify(t.Context(), peer.token(t, "peer-user"))
		return err
	}
	probe := func() error { return v.CheckIssuerKeys(t.Context()) }
	// probesFetchAtMostPerBackoff probes for a while and bounds the fetches.
	probesFetchAtMostPerBackoff := func() {
		hits, start := provider.hits.Load(), time.Now()
		for time.Since(start) < 300*time.Millisecond {
			require.Error(t, probe())
		}
		require.LessOrEqual(t, provider.hits.Load()-hits, 2*int32(time.Since(start)/backoff)+2, "thousands of probes, a few fetches")
	}

	require.NoError(t, probe(), "an issuer no token needed yet is not fetched")
	require.Zero(t, provider.hits.Load())

	// Down before its keys were ever fetched.
	provider.mode.Store("503")
	require.ErrorIs(t, verify(), errmodel.E(errmodel.CodeIssuerKeysUnavailable))
	probesFetchAtMostPerBackoff()
	provider.mode.Store("up")
	require.Eventually(t, func() bool { return probe() == nil }, 5*time.Second, 10*time.Millisecond)
	hits := provider.hits.Load()
	require.NoError(t, verify())
	require.Equal(t, hits, provider.hits.Load(), "the probe loaded the keys")

	// Down after, with stale keys: probes alone see it fail and recover.
	provider.mode.Store("503")
	clock.advance(cachepolicy.IssuerKeys.RefreshAfter + time.Minute)
	require.Eventually(t, func() bool { return probe() != nil }, 5*time.Second, 10*time.Millisecond)
	require.ErrorContains(t, probe(), "stale")
	probesFetchAtMostPerBackoff()
	provider.mode.Store("up")
	require.Eventually(t, func() bool { return probe() == nil }, 5*time.Second, 10*time.Millisecond)
	require.True(t, v.IssuerKeyStatuses()[0].Fresh)
	require.NoError(t, verify())
}
