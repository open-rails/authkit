package authhttp

import (
	"context"
	"crypto"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/open-rails/authkit/embedded"
	authcore "github.com/open-rails/authkit/internal/authcore"
	jwtkit "github.com/open-rails/authkit/jwt"
	oidckit "github.com/open-rails/authkit/oidc"
	"github.com/stretchr/testify/require"
)

func newTestServiceBaseURL(t *testing.T, baseURL string) *Service {
	t.Helper()
	signer, err := jwtkit.NewRSASigner(2048, "test-kid")
	require.NoError(t, err)
	ks := authcore.Keyset{Active: signer, PublicKeys: map[string]crypto.PublicKey{"test-kid": signer.PublicKey()}}
	opts := embedded.Config{Token: embedded.TokenConfig{Issuer: "https://example.com", IssuedAudiences: []string{"test-app"}, ExpectedAudiences: []string{"test-app"}, AccessTokenDuration: time.Hour}, Frontend: embedded.FrontendConfig{BaseURL: baseURL}, Registration: embedded.RegistrationConfig{Verification: embedded.RegistrationVerificationNone}}
	coreSvc := authcore.NewService(opts, ks)
	ver := NewVerifier(WithSkew(5 * time.Second))
	_ = ver.AddIssuer(opts.Token.Issuer, opts.Token.ExpectedAudiences, IssuerOptions{RawKeys: coreSvc.PublicKeysByKID()})
	ver.WithService(coreSvc)
	return &Service{svc: coreSvc, verifier: ver}
}

// --- F2: redirect_uri derived from trusted config, never X-Forwarded-* ---

func TestBuildRedirectURI_UsesBaseURLNotForwardedHeaders(t *testing.T) {
	s := newTestServiceBaseURL(t, "https://auth.example")
	r := httptest.NewRequest(http.MethodGet, "/api/v1/oidc/google/login", nil)
	r.Host = "internal.local"
	r.Header.Set("X-Forwarded-Host", "attacker.example")
	r.Header.Set("X-Forwarded-Proto", "https")
	got := s.buildRedirectURI(r, "google")
	require.Equal(t, "https://auth.example/api/v1/oidc/google/callback", got)
	require.NotContains(t, got, "attacker.example")
}

func TestBuildRedirectURI_DevFallbackIgnoresForwardedHost(t *testing.T) {
	// #237: BaseURL now defaults from a well-formed issuer in the ONE
	// normalization pass, so "no BaseURL" requires a non-URL issuer too.
	s := newTestServiceNoBaseOrigin(t) // no base origin -> fall back to the connection host
	r := httptest.NewRequest(http.MethodGet, "/oidc/google/login", nil)
	r.Host = "localhost:8080"
	r.Header.Set("X-Forwarded-Host", "attacker.example")
	got := s.buildRedirectURI(r, "google")
	require.Equal(t, "http://localhost:8080/oidc/google/callback", got)
	require.NotContains(t, got, "attacker.example")
}

// --- F3: state bound to the browser via cookie ---

func TestStateCookieMatches(t *testing.T) {
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	require.False(t, stateCookieMatches(r, "abc"), "no cookie present")
	r.AddCookie(&http.Cookie{Name: oauthStateCookie, Value: "abc"})
	require.True(t, stateCookieMatches(r, "abc"))
	require.False(t, stateCookieMatches(r, "xyz"), "value mismatch must fail")
	require.False(t, stateCookieMatches(r, ""), "empty state never matches")
}

func TestOIDCCallback_RejectsWithoutStateCookie(t *testing.T) {
	s := newTestService(t)
	enableTestOIDCProvider(s)
	h := s.OIDCHandler()
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/oidc/google/callback?state=abc&code=xyz", nil)
	h.ServeHTTP(w, r)
	require.Equal(t, http.StatusBadRequest, w.Code)
	require.Contains(t, w.Body.String(), "invalid_state")
}

func TestOIDCCallback_StateCookiePassesCookieGate(t *testing.T) {
	s := newTestService(t)
	enableTestOIDCProvider(s)
	require.NoError(t, s.stateCache().Put(context.Background(), "good-state", oidckit.StateData{Provider: "google"}))
	h := s.OIDCHandler()
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/oidc/google/callback?state=good-state&code=xyz", nil)
	r.AddCookie(&http.Cookie{Name: oauthStateCookie, Value: "good-state"})
	h.ServeHTTP(w, r)
	// With a matching cookie the request passes the F3 gate and fails later (no real
	// IdP configured), so it must NOT be the invalid_state cookie rejection.
	require.NotContains(t, w.Body.String(), "invalid_state")
}

// --- F6: X-Forwarded-For right-most untrusted hop ---

func TestClientIPFromForwardedHeaders_RightmostUntrustedHop(t *testing.T) {
	trusted := []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")}
	fn := ClientIPFromForwardedHeaders(trusted)

	// Trusted proxy peer; attacker injected 9.9.9.9 as the left-most (client-supplied)
	// XFF entry, the proxy appended the real client 8.8.8.8 on the right.
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.RemoteAddr = "10.1.2.3:1111"
	r.Header.Set("X-Forwarded-For", "9.9.9.9, 8.8.8.8")
	require.Equal(t, "8.8.8.8", fn(r), "must use right-most untrusted hop, not spoofable left-most")

	// A chain of trusted proxies on the right is skipped to the first untrusted hop.
	r2 := httptest.NewRequest(http.MethodGet, "/", nil)
	r2.RemoteAddr = "10.1.2.3:1111"
	r2.Header.Set("X-Forwarded-For", "9.9.9.9, 8.8.8.8, 10.0.0.9")
	require.Equal(t, "8.8.8.8", fn(r2))

	// Untrusted peer: forwarded headers are ignored entirely; the peer is used.
	r3 := httptest.NewRequest(http.MethodGet, "/", nil)
	r3.RemoteAddr = "8.8.4.4:2222"
	r3.Header.Set("X-Forwarded-For", "9.9.9.9")
	require.Equal(t, "8.8.4.4", fn(r3))
}

// --- F7: request body size cap ---

func TestDecodeJSON_RejectsOversizedBody(t *testing.T) {
	big := `{"x":"` + strings.Repeat("a", (1<<20)+1024) + `"}`
	r := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(big))
	var dst struct {
		X string `json:"x"`
	}
	require.Error(t, decodeJSON(r, &dst), "a body over the cap must be rejected")
}

func TestDecodeJSON_AcceptsSmallBody(t *testing.T) {
	r := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(`{"x":"hi"}`))
	var dst struct {
		X string `json:"x"`
	}
	require.NoError(t, decodeJSON(r, &dst))
	require.Equal(t, "hi", dst.X)
}
