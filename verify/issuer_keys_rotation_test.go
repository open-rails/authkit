package verify

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/open-rails/authkit/internal/cachepolicy"
	"github.com/open-rails/authkit/keys"
	"github.com/stretchr/testify/require"
)

// A key the issuer starts publishing verifies at once (an unknown kid
// refetches, at most once per IssuerKeysRefetchMin); one it stops publishing
// stops verifying at the next refresh.
func TestPeerJWKSRotation(t *testing.T) {
	a, b, c := rsaSigner(t, "a"), rsaSigner(t, "b"), rsaSigner(t, "c")
	f := newPeerFixture(t)
	f.serveKeys(jwkOf(a))
	code, _ := f.call(f.token(a, f.issuer, nil))
	require.Equal(t, http.StatusOK, code)

	f.serveKeys(jwkOf(a), jwkOf(b))
	hits := f.jwksHits.Load()
	code, _ = f.call(f.token(b, f.issuer, nil))
	require.Equal(t, http.StatusOK, code, "a new kid refetches at once")
	require.Equal(t, hits+1, f.jwksHits.Load())

	f.serveKeys(jwkOf(a), jwkOf(b), jwkOf(c))
	for range 5 {
		code, _ = f.call(f.token(c, f.issuer, nil))
		require.Equal(t, http.StatusUnauthorized, code, "refetches are throttled")
	}
	require.Equal(t, hits+1, f.jwksHits.Load())
	f.advance(cachepolicy.IssuerKeysRefetchMin)
	code, _ = f.call(f.token(c, f.issuer, nil))
	require.Equal(t, http.StatusOK, code)

	f.serveKeys(jwkOf(c))
	code, _ = f.call(f.token(a, f.issuer, nil))
	require.Equal(t, http.StatusOK, code, "cached until the next refresh")
	f.pastRefresh()
	require.Eventually(t, func() bool { code, _ := f.call(f.token(a, f.issuer, nil)); return code == http.StatusUnauthorized }, 5*time.Second, 10*time.Millisecond)
	code, _ = f.call(f.token(c, f.issuer, nil))
	require.Equal(t, http.StatusOK, code)
}

// A key replaced under the same kid verifies after one refetch: the failed
// signature forces it.
func TestPeerJWKSRotationKeepingKID(t *testing.T) {
	old, rotated := rsaSigner(t, "same"), rsaSigner(t, "same")
	f := newPeerFixture(t)
	f.serveKeys(jwkOf(old))
	code, _ := f.call(f.token(old, f.issuer, nil))
	require.Equal(t, http.StatusOK, code)

	f.serveKeys(jwkOf(rotated))
	code, _ = f.call(f.token(rotated, f.issuer, nil))
	require.Equal(t, http.StatusOK, code)
	code, _ = f.call(f.token(old, f.issuer, nil))
	require.Equal(t, http.StatusUnauthorized, code)
}

// Re-registering an issuer at a new JWKS endpoint never serves the keys
// fetched from the old one.
func TestPeerJWKSNewEndpointDropsOldKeys(t *testing.T) {
	a, b := rsaSigner(t, "a"), rsaSigner(t, "b")
	f := newPeerFixture(t)
	f.serveKeys(jwkOf(a))
	code, _ := f.call(f.token(a, f.issuer, nil))
	require.Equal(t, http.StatusOK, code)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(keys.JWKS{Keys: []keys.JWK{jwkOf(b)}})
	}))
	t.Cleanup(srv.Close)
	require.NoError(t, f.v.AddIssuer(f.issuer, []string{f.aud}, IssuerOptions{JWKSURI: srv.URL}))
	code, _ = f.call(f.token(a, f.issuer, nil))
	require.Equal(t, http.StatusUnauthorized, code)
	code, _ = f.call(f.token(b, f.issuer, nil))
	require.Equal(t, http.StatusOK, code)
	require.Equal(t, srv.URL, f.status().JWKSURI)
}
