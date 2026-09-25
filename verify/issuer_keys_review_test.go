package verify

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	jwt "github.com/golang-jwt/jwt/v5"
	authkit "github.com/open-rails/authkit"
	"github.com/open-rails/authkit/jwtkit"
	"github.com/stretchr/testify/require"
)

// peerFixture is a peer issuer whose JWKS endpoint answers whatever the test
// installs, verified through the real Required middleware with a movable clock.
type peerFixture struct {
	t        *testing.T
	v        *Verifier
	issuer   string
	aud      string
	serve    atomic.Value // http.HandlerFunc
	offset   atomic.Int64
	local    *jwtkit.RSASigner
	handler  http.Handler
	jwksHits atomic.Int32
}

func newPeerFixture(t *testing.T, opts IssuerOptions) *peerFixture {
	f := &peerFixture{t: t, issuer: "https://peer.example", aud: "resource"}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.jwksHits.Add(1)
		f.serve.Load().(http.HandlerFunc)(w, r)
	}))
	t.Cleanup(srv.Close)
	local, err := jwtkit.NewRSASigner(2048, "local")
	require.NoError(t, err)
	f.local = local
	f.v = NewVerifier()
	f.v.now = func() time.Time { return time.Now().Add(time.Duration(f.offset.Load())) }
	f.v.jwksAttemptTimeout, f.v.jwksBackoffBase, f.v.jwksBackoffMax = 500*time.Millisecond, 10*time.Millisecond, 50*time.Millisecond
	require.NoError(t, f.v.AddIssuer("https://local.example", []string{f.aud}, IssuerOptions{IsLocal: true, RawKeys: map[string]crypto.PublicKey{"local": local.PublicKey()}}))
	opts.JWKSURI = srv.URL
	require.NoError(t, f.v.AddIssuer(f.issuer, []string{f.aud}, opts))
	f.handler = Required(f.v)(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) }))
	return f
}

func (f *peerFixture) serveKeys(keys ...jwtkit.JWK) {
	f.serve.Store(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(jwtkit.JWKS{Keys: keys})
	}))
}

func (f *peerFixture) serveStatus(status int, body string) {
	f.serve.Store(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(status)
		_, _ = w.Write([]byte(body))
	}))
}

func (f *peerFixture) advance(d time.Duration) { f.offset.Add(int64(d)) }

func (f *peerFixture) token(signer jwtkit.Signer, iss string, claims jwt.MapClaims) string {
	now := time.Now() // claim times are checked against the real clock
	base := jwt.MapClaims{"sub": "user", "iss": iss, "aud": f.aud, "iat": now.Unix(), "exp": now.Add(time.Hour).Unix()}
	for k, v := range claims {
		base[k] = v
	}
	tok, err := jwtkit.SignWithType(context.Background(), signer, base, jwtkit.AccessTokenType, true)
	require.NoError(f.t, err)
	return tok
}

func (f *peerFixture) call(token string) (int, string) {
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()
	f.handler.ServeHTTP(rec, req)
	var env authkit.ErrorEnvelope
	_ = json.Unmarshal(rec.Body.Bytes(), &env)
	return rec.Code, env.Error.Code
}

func (f *peerFixture) status() IssuerKeyStatus {
	for _, st := range f.v.IssuerKeyStatuses() {
		if st.Issuer == f.issuer {
			return st
		}
	}
	f.t.Fatal("no status for peer")
	return IssuerKeyStatus{}
}

func rsaSigner(t *testing.T, kid string) *jwtkit.RSASigner {
	s, err := jwtkit.NewRSASigner(2048, kid)
	require.NoError(t, err)
	return s
}

func jwkOf(s *jwtkit.RSASigner) jwtkit.JWK {
	return jwtkit.PublicToJWK(s.PublicKey(), s.KID(), "RS256")
}

// A JSON JWKS is authoritative: valid keys are installed (bad ones skipped),
// and one with no valid keys drops the cache and fails closed. Stale keys
// survive anything that is not a JSON JWKS.
func TestPeerJWKSAuthoritativeResponses(t *testing.T) {
	a, b := rsaSigner(t, "a"), rsaSigner(t, "b")
	weak, err := rsa.GenerateKey(rand.Reader, 1024)
	require.NoError(t, err)
	f := newPeerFixture(t, IssuerOptions{CacheTTL: time.Minute})
	f.serveKeys(jwkOf(a))
	code, _ := f.call(f.token(a, f.issuer, nil))
	require.Equal(t, http.StatusOK, code)

	// refresh moves past CacheTTL and waits for the background refresh a peer
	// request triggers to record an attempt.
	refresh := func() {
		f.advance(2 * time.Minute)
		mark := f.v.now()
		f.call(f.token(a, f.issuer, nil))
		require.Eventually(t, func() bool { return !f.status().CheckedAt.Before(mark) }, 5*time.Second, 5*time.Millisecond)
	}

	// Transient failures keep the stale keys.
	for _, status := range []int{http.StatusServiceUnavailable, http.StatusTooManyRequests} {
		f.serveStatus(status, "")
		refresh()
		code, _ = f.call(f.token(a, f.issuer, nil))
		require.Equal(t, http.StatusOK, code, status)
	}

	// One weak and one unsupported key are skipped; the valid key is installed
	// and the rotated-out key stops verifying.
	f.serveKeys(jwtkit.PublicToJWK(&weak.PublicKey, "weak", "RS256"), jwtkit.JWK{Kty: "oct", Kid: "sym"}, jwkOf(b))
	refresh()
	require.Eventually(t, func() bool { code, _ := f.call(f.token(b, f.issuer, nil)); return code == http.StatusOK }, 5*time.Second, 10*time.Millisecond)
	code, _ = f.call(f.token(a, f.issuer, nil))
	require.Equal(t, http.StatusUnauthorized, code)

	// A JSON JWKS without usable keys drops the cache: fail closed.
	for name, serve := range map[string]func(){
		"empty":       func() { f.serveKeys() },
		"unsupported": func() { f.serveKeys(jwtkit.JWK{Kty: "oct", Kid: "sym"}) },
		"weak":        func() { f.serveKeys(jwtkit.PublicToJWK(&weak.PublicKey, "weak", "RS256")) },
	} {
		f.serveKeys(jwkOf(b))
		refresh()
		require.Eventually(t, func() bool { code, _ := f.call(f.token(b, f.issuer, nil)); return code == http.StatusOK }, 5*time.Second, 10*time.Millisecond, name)
		serve()
		refresh()
		require.Eventually(t, func() bool { return f.status().Keys == 0 }, 5*time.Second, 10*time.Millisecond, name)
		code, errCode := f.call(f.token(b, f.issuer, nil))
		require.Equal(t, http.StatusServiceUnavailable, code, name)
		require.Equal(t, string(authkit.CodeIssuerKeysUnavailable), errCode, name)
	}
}

// Defaults: MaxStale is 4h, and never below CacheTTL — keys inside their TTL
// always verify.
func TestPeerJWKSMaxStaleDefaultsAndFloor(t *testing.T) {
	a := rsaSigner(t, "a")
	f := newPeerFixture(t, IssuerOptions{})
	f.serveKeys(jwkOf(a))
	code, _ := f.call(f.token(a, f.issuer, nil))
	require.Equal(t, http.StatusOK, code)
	require.Equal(t, 4*time.Hour, f.status().MaxStale)

	g := newPeerFixture(t, IssuerOptions{CacheTTL: 2 * time.Hour, MaxStale: time.Hour})
	g.serveKeys(jwkOf(a))
	code, _ = g.call(g.token(a, g.issuer, nil))
	require.Equal(t, http.StatusOK, code)
	require.Equal(t, 2*time.Hour, g.status().MaxStale)
	g.advance(90 * time.Minute)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	_, err := g.v.Verify(ctx, g.token(a, g.issuer, nil))
	require.NoError(t, err)
}

// An expired or wrong-audience token is rejected as such (401) even when the
// issuer's keys are unavailable; only an otherwise-valid token gets 503.
func TestPeerJWKSUnavailableChecksClaimsFirst(t *testing.T) {
	a := rsaSigner(t, "a")
	f := newPeerFixture(t, IssuerOptions{})
	f.serveStatus(http.StatusServiceUnavailable, "")
	code, errCode := f.call(f.token(a, f.issuer, jwt.MapClaims{"exp": time.Now().Add(-time.Hour).Unix()}))
	require.Equal(t, http.StatusUnauthorized, code)
	require.Equal(t, string(authkit.CodeAccessTokenExpired), errCode)
	code, errCode = f.call(f.token(a, f.issuer, jwt.MapClaims{"aud": "someone-else"}))
	require.Equal(t, http.StatusUnauthorized, code)
	require.Equal(t, string(authkit.CodeBadAudience), errCode)
	code, errCode = f.call(f.token(a, f.issuer, nil))
	require.Equal(t, http.StatusServiceUnavailable, code)
	require.Equal(t, string(authkit.CodeIssuerKeysUnavailable), errCode)
}

// A slower, older fetch can never overwrite the keys a newer fetch installed.
func TestPeerJWKSOlderFetchCannotOverwriteNewer(t *testing.T) {
	a, b := rsaSigner(t, "a"), rsaSigner(t, "b")
	f := newPeerFixture(t, IssuerOptions{})
	release := make(chan struct{})
	var n atomic.Int32
	f.serve.Store(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if n.Add(1) == 1 {
			<-release
			_ = json.NewEncoder(w).Encode(jwtkit.JWKS{Keys: []jwtkit.JWK{jwkOf(a)}})
			return
		}
		_ = json.NewEncoder(w).Encode(jwtkit.JWKS{Keys: []jwtkit.JWK{jwkOf(b)}})
	}))
	f.v.mu.RLock()
	c, ie := f.v.byIss[f.issuer], f.v.issuers[f.issuer]
	f.v.mu.RUnlock()
	older := make(chan error, 1)
	go func() { older <- f.v.refreshIssuerKeys(context.Background(), f.issuer, c, ie) }()
	require.Eventually(t, func() bool { return n.Load() == 1 }, 5*time.Second, time.Millisecond)
	require.NoError(t, f.v.refreshIssuerKeys(context.Background(), f.issuer, c, ie))
	close(release)
	<-older
	f.v.mu.RLock()
	_, hasA := c.pubByKID["a"]
	_, hasB := c.pubByKID["b"]
	f.v.mu.RUnlock()
	require.False(t, hasA)
	require.True(t, hasB)
}

// Run with -race: a request that gives up while a refresh is in flight must not
// read the key cache outside the lock the refresh writes under.
func TestPeerJWKSCancelledWaitDoesNotRaceRefresh(t *testing.T) {
	a := rsaSigner(t, "a")
	f := newPeerFixture(t, IssuerOptions{CacheTTL: time.Minute, MaxStale: time.Hour})
	f.serveKeys(jwkOf(a))
	code, _ := f.call(f.token(a, f.issuer, nil))
	require.Equal(t, http.StatusOK, code)

	for range 5 {
		f.advance(2 * time.Hour) // past MaxStale, last fetch succeeded
		served := make(chan struct{})
		f.serve.Store(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			time.Sleep(100 * time.Millisecond)
			_ = json.NewEncoder(w).Encode(jwtkit.JWKS{Keys: []jwtkit.JWK{jwkOf(a)}})
			close(served)
		}))
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		_, err := f.v.Verify(ctx, f.token(a, f.issuer, nil))
		require.ErrorIs(t, err, authkit.E(authkit.CodeIssuerKeysUnavailable))
		<-served
		time.Sleep(100 * time.Millisecond) // let the refresh publish before touching the verifier again
		code, _ = f.call(f.token(a, f.issuer, nil))
		require.Equal(t, http.StatusOK, code)
	}
}

// A 4xx or a non-JSON 200 is not an answer about the key set: stale keys keep
// verifying within MaxStale and the failure is reported. A JSON JWKS that no
// longer lists a key revokes it.
func TestPeerJWKSNonJWKSResponsesAreTransient(t *testing.T) {
	a, b := rsaSigner(t, "a"), rsaSigner(t, "b")
	f := newPeerFixture(t, IssuerOptions{CacheTTL: time.Minute})
	f.serveKeys(jwkOf(a))
	code, _ := f.call(f.token(a, f.issuer, nil))
	require.Equal(t, http.StatusOK, code)

	for name, serve := range map[string]func(){
		"404":      func() { f.serveStatus(http.StatusNotFound, "not found") },
		"403":      func() { f.serveStatus(http.StatusForbidden, "") },
		"not json": func() { f.serveStatus(http.StatusOK, "<html>captive portal</html>") },
	} {
		serve()
		f.advance(2 * time.Minute)
		mark := f.v.now()
		code, _ = f.call(f.token(a, f.issuer, nil))
		require.Equal(t, http.StatusOK, code, name)
		require.Eventually(t, func() bool { return !f.status().CheckedAt.Before(mark) }, 5*time.Second, 5*time.Millisecond, name)
		st := f.status()
		require.Equal(t, 1, st.Keys, name)
		require.Positive(t, st.Failures, name)
		require.NotEmpty(t, st.LastError, name)
		require.False(t, st.Expired, name)
		require.ErrorContains(t, f.v.CheckIssuerKeys(t.Context()), "stale", name)
		code, _ = f.call(f.token(a, f.issuer, nil))
		require.Equal(t, http.StatusOK, code, name)
	}

	f.serveKeys(jwkOf(b))
	require.Eventually(t, func() bool { return f.v.CheckIssuerKeys(t.Context()) == nil }, 5*time.Second, 10*time.Millisecond)
	code, _ = f.call(f.token(b, f.issuer, nil))
	require.Equal(t, http.StatusOK, code)
	code, _ = f.call(f.token(a, f.issuer, nil))
	require.Equal(t, http.StatusUnauthorized, code)
}
