package verify

import (
	"context"
	"crypto"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	jwt "github.com/golang-jwt/jwt/v5"
	"github.com/open-rails/authkit/iam"
	"github.com/open-rails/authkit/internal/errmodel"
	"github.com/open-rails/authkit/jwtkit"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const testAudience = "test-app"

// testIssuer is an issuer URL and the key its tokens are signed with.
type testIssuer struct {
	url    string
	signer *jwtkit.RSASigner
}

func newTestIssuer(t *testing.T, url string) testIssuer {
	t.Helper()
	signer, err := jwtkit.NewRSASigner(2048, url)
	require.NoError(t, err)
	return testIssuer{url: url, signer: signer}
}

func (i testIssuer) token(t *testing.T, sub string) string {
	t.Helper()
	now := time.Now()
	token, err := jwtkit.SignWithType(context.Background(), i.signer, jwt.MapClaims{
		"sub": sub, "iss": i.url, "aud": testAudience, "iat": now.Unix(), "exp": now.Add(time.Hour).Unix(),
	}, jwtkit.AccessTokenType, true)
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
	local, peer := newTestIssuer(t, "https://local.example"), newTestIssuer(t, "https://peer.example")
	provider := newJWKSProvider(t, peer.signer)

	v := NewVerifier()
	v.jwksAttemptTimeout, v.jwksBackoffBase, v.jwksBackoffMax = 300*time.Millisecond, 20*time.Millisecond, 100*time.Millisecond
	require.NoError(t, v.AddIssuer(local.url, []string{testAudience}, IssuerOptions{
		IsLocal: true, RawKeys: map[string]crypto.PublicKey{local.signer.KID(): local.signer.PublicKey()},
	}))
	require.NoError(t, v.AddIssuer(peer.url, []string{testAudience}, IssuerOptions{JWKSURI: provider.URL, CacheTTL: 100 * time.Millisecond}))

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
	// then 503 issuer_keys_unavailable; later requests fail fast.
	provider.mode.Store("hang")
	code, errCode, took := call(peerToken)
	require.Equal(t, http.StatusServiceUnavailable, code)
	require.Equal(t, string(errmodel.CodeIssuerKeysUnavailable), errCode)
	require.Less(t, took, 2*time.Second)
	provider.mode.Store("reset")
	for range 5 {
		code, errCode, took = call(peerToken)
		require.Equal(t, http.StatusServiceUnavailable, code)
		require.Equal(t, string(errmodel.CodeIssuerKeysUnavailable), errCode)
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

// Stale peer keys verify only up to MaxStale after the last successful fetch;
// past it the peer fails closed (so blocking our refetch cannot keep a revoked
// key valid) and recovers on the next successful refetch.
func TestPeerJWKSStaleKeysCappedAtMaxStale(t *testing.T) {
	local, peer := newTestIssuer(t, "https://local.example"), newTestIssuer(t, "https://peer.example")
	provider := newJWKSProvider(t, peer.signer)

	var offset atomic.Int64
	v := NewVerifier()
	v.now = func() time.Time { return time.Now().Add(time.Duration(offset.Load())) }
	v.jwksAttemptTimeout, v.jwksBackoffBase, v.jwksBackoffMax = 300*time.Millisecond, 10*time.Millisecond, 50*time.Millisecond
	require.NoError(t, v.AddIssuer(local.url, []string{testAudience}, IssuerOptions{
		IsLocal: true, RawKeys: map[string]crypto.PublicKey{local.signer.KID(): local.signer.PublicKey()},
	}))
	require.NoError(t, v.AddIssuer(peer.url, []string{testAudience}, IssuerOptions{JWKSURI: provider.URL, CacheTTL: time.Minute, MaxStale: time.Hour}))

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

	code, _ := call(peerToken)
	require.Equal(t, http.StatusOK, code)

	provider.mode.Store("503")
	offset.Store(int64(30 * time.Minute)) // past CacheTTL, inside MaxStale
	code, _ = call(peerToken)
	require.Equal(t, http.StatusOK, code)
	require.Eventually(t, func() bool { return status().Failures > 0 }, 5*time.Second, 10*time.Millisecond)
	st := status()
	require.False(t, st.Expired)
	require.GreaterOrEqual(t, st.Age, 30*time.Minute)
	require.ErrorContains(t, v.CheckIssuerKeys(t.Context()), "stale")
	code, _ = call(peerToken)
	require.Equal(t, http.StatusOK, code)

	offset.Store(int64(61 * time.Minute)) // past MaxStale
	code, errCode := call(peerToken)
	require.Equal(t, http.StatusServiceUnavailable, code)
	require.Equal(t, string(errmodel.CodeIssuerKeysUnavailable), errCode)
	code, _ = call(localToken)
	require.Equal(t, http.StatusOK, code)
	require.True(t, status().Expired)
	require.ErrorContains(t, v.CheckIssuerKeys(t.Context()), "failing closed")

	provider.mode.Store("up")
	require.Eventually(t, func() bool { return v.CheckIssuerKeys(t.Context()) == nil }, 5*time.Second, 10*time.Millisecond)
	st = status()
	require.False(t, st.Expired)
	require.Less(t, st.Age, time.Minute)
	code, _ = call(peerToken)
	require.Equal(t, http.StatusOK, code)
}
