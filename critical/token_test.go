package critical_test

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/open-rails/authkit"
	"github.com/open-rails/authkit/authtest"
	"github.com/open-rails/authkit/iam"
	"github.com/open-rails/authkit/internal/cachepolicy"
	"github.com/open-rails/authkit/internal/testclock"
	"github.com/open-rails/authkit/keys"
	"github.com/open-rails/authkit/verify"
)

func jwtParts(t *testing.T, raw string) (map[string]any, map[string]any) {
	t.Helper()
	parts := strings.Split(raw, ".")
	if len(parts) != 3 {
		t.Fatal("fixture is not an issued JWT")
	}
	var header, claims map[string]any
	h, err := base64.RawURLEncoding.DecodeString(parts[0])
	noError(t, err)
	p, err := base64.RawURLEncoding.DecodeString(parts[1])
	noError(t, err)
	decode(t, h, &header)
	decode(t, p, &claims)
	return header, claims
}
func signJWT(t *testing.T, signer keys.Signer, header, claims map[string]any) string {
	t.Helper()
	h, err := json.Marshal(header)
	noError(t, err)
	p, err := json.Marshal(claims)
	noError(t, err)
	input := base64.RawURLEncoding.EncodeToString(h) + "." + base64.RawURLEncoding.EncodeToString(p)
	signature, err := signer.Sign(t.Context(), []byte(input))
	noError(t, err)
	return input + "." + base64.RawURLEncoding.EncodeToString(signature)
}
func jwtFixture(t *testing.T) *fixture {
	return newFixture(t, authtest.WithConfig(func(c *authkit.Config) {
		c.AuthorizationServer.Clients = []authkit.OAuthClientConfig{{ID: authtest.Audience, RedirectURIs: []string{"https://client.example/callback"}}}
	}))
}
func expectTokenError(t *testing.T, err error, code string) {
	t.Helper()
	e, ok := iam.AsError(err)
	if !ok || e.Status() != http.StatusUnauthorized || e.Code() != code {
		t.Fatalf("token refusal=%v, want401/%s", err, code)
	}
}
func fixtureIDToken(t *testing.T, f *fixture, raw string) string {
	t.Helper()
	h, c := jwtParts(t, raw)
	h["typ"] = "JWT"
	c["azp"] = authtest.Audience
	c["aud"] = []string{authtest.Audience}
	c["nonce"] = "critical-expected-nonce"
	return signJWT(t, f.deps.KeySource.ActiveSigner(), h, c)
}

func TestCriticalTokenProfiles(t *testing.T) {
	f := jwtFixture(t)
	t.Run("AK-J13-C01_access_resource_and_ID_profiles_have_distinct_contracts", func(t *testing.T) {
		u := f.user(t)
		session := f.signIn(t, u)
		native, err := f.auth.Verify(t.Context(), session.AccessToken)
		noError(t, err)
		if native.UserID != u.ID || native.SessionID == "" {
			t.Fatal("native access profile lost its real sign-in")
		}
		request, err := http.NewRequestWithContext(t.Context(), "GET", f.server.URL+"/resource", nil)
		noError(t, err)
		request.Header.Set("Authorization", "Bearer "+session.AccessToken)
		fromRequest, err := f.auth.VerifyRequest(request)
		noError(t, err)
		if fromRequest.UserID != u.ID || fromRequest.SessionID != native.SessionID {
			t.Fatal("request verifier changed the signed subject or session")
		}
		verified, err := f.auth.AuthenticateRequest(t.Context(), request)
		noError(t, err)
		if verified.Identity().Subject != u.ID {
			t.Fatal("public request authentication changed subject")
		}
		id, err := f.auth.VerifyIDToken(t.Context(), fixtureIDToken(t, f, session.AccessToken))
		noError(t, err)
		if id.Subject != u.ID || id.ClientID != authtest.Audience || id.SessionID != native.SessionID || id.Nonce != "critical-expected-nonce" {
			t.Fatal("ID-token profile lost its client/session/nonce")
		}
		h, c := jwtParts(t, session.AccessToken)
		h["typ"] = "at+jwt"
		c["aud"] = []string{"orders-api"}
		c["client_id"] = "registered-resource-client"
		c["scope"] = "orders:read"
		v := verify.NewVerifier()
		defer v.Close()
		noError(t, v.AddIssuer(authtest.Issuer, []string{"orders-api"}, verify.IssuerOptions{KeySource: f.deps.KeySource}))
		resource, err := v.Verify(t.Context(), signJWT(t, f.deps.KeySource.ActiveSigner(), h, c))
		noError(t, err)
		if !resource.IsResourceToken() || !resource.HasScope("orders:read") || resource.HasScope("orders:write") {
			t.Fatal("resource profile widened or lost its explicit scope")
		}
	})
	t.Run("AK-J13-C02_signature_algorithm_type_and_structure_confusion_fail", func(t *testing.T) {
		u := f.user(t)
		raw := f.signIn(t, u).AccessToken
		for _, typ := range []string{"JWT", "refresh+jwt", ""} {
			h, c := jwtParts(t, raw)
			h["typ"] = typ
			_, err := f.auth.Verify(t.Context(), signJWT(t, f.deps.KeySource.ActiveSigner(), h, c))
			if err == nil {
				t.Fatalf("access verifier admitted token type%q", typ)
			}
		}
		for _, alg := range []string{"none", "HS256"} {
			h, c := jwtParts(t, raw)
			h["alg"] = alg
			_, err := f.auth.Verify(t.Context(), signJWT(t, f.deps.KeySource.ActiveSigner(), h, c))
			expectTokenError(t, err, "invalid_token")
		}
		parts := strings.Split(raw, ".")
		signature := parts[2]
		replacement := "A"
		if strings.HasPrefix(signature, replacement) {
			replacement = "B"
		}
		parts[2] = replacement + signature[1:]
		for _, bad := range []string{"not-a-token", "a.b.c", strings.Join(parts, ".")} {
			_, err := f.auth.Verify(t.Context(), bad)
			expectTokenError(t, err, "invalid_token")
		}
		h, c := jwtParts(t, raw)
		delete(c, "sub")
		_, err := f.auth.Verify(t.Context(), signJWT(t, f.deps.KeySource.ActiveSigner(), h, c))
		expectTokenError(t, err, "missing_sub")
	})
	t.Run("AK-J13-C03_issuer_audience_and_lifetime_are_not_interchangeable", func(t *testing.T) {
		u := f.user(t)
		raw := f.signIn(t, u).AccessToken
		for _, tc := range []struct {
			name, key string
			value     any
			code      string
		}{{"issuer", "iss", "https://untrusted.example", "invalid_token"}, {"audience", "aud", []string{"other-service"}, "bad_audience"}, {"expired", "exp", time.Now().Add(-2 * time.Minute).Unix(), "token_expired"}, {"not-before", "nbf", time.Now().Add(2 * time.Minute).Unix(), "token_not_yet_valid"}, {"issued-in-future", "iat", time.Now().Add(2 * time.Minute).Unix(), "token_not_yet_valid"}} {
			t.Run(tc.name, func(t *testing.T) {
				h, c := jwtParts(t, raw)
				c[tc.key] = tc.value
				_, err := f.auth.Verify(t.Context(), signJWT(t, f.deps.KeySource.ActiveSigner(), h, c))
				expectTokenError(t, err, tc.code)
			})
		}
		h, c := jwtParts(t, raw)
		delete(c, "exp")
		_, err := f.auth.Verify(t.Context(), signJWT(t, f.deps.KeySource.ActiveSigner(), h, c))
		expectTokenError(t, err, "missing_exp")
	})
	t.Run("AK-J13-C04_JWKS_rotation_and_outage_have_bounded_trust", func(t *testing.T) {
		clock := testclock.Wall()
		oldPolicy := cachepolicy.IssuerKeys
		cachepolicy.IssuerKeys.Clock = clock
		t.Cleanup(func() { cachepolicy.IssuerKeys = oldPolicy })
		first := f.deps.KeySource.ActiveSigner()
		private, err := rsa.GenerateKey(rand.Reader, 2048)
		noError(t, err)
		second, err := keys.SignerFromKey(first.KID(), private)
		noError(t, err)
		var mu sync.RWMutex
		current := first
		down := false
		peer := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			mu.RLock()
			defer mu.RUnlock()
			if down {
				http.Error(w, "peer unavailable", http.StatusServiceUnavailable)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(keys.JWKS{Keys: []keys.JWK{keys.PublicJWK(current.Public(), current.KID(), current.Algorithm())}})
		}))
		t.Cleanup(peer.Close)
		v := verify.NewVerifier(verify.WithHTTPClient(peer.Client()))
		defer v.Close()
		options := verify.IssuerOptions{JWKSURI: peer.URL, IsLocal: true}
		noError(t, v.AddIssuer(authtest.Issuer, []string{authtest.Audience}, options))
		u := f.user(t)
		original := f.signIn(t, u).AccessToken
		_, err = v.Verify(t.Context(), original)
		noError(t, err)
		h, c := jwtParts(t, original)
		rotated := signJWT(t, second, h, c)
		mu.Lock()
		current = second
		mu.Unlock()
		clock.Advance(time.Minute)
		_, err = v.Verify(t.Context(), rotated)
		noError(t, err)
		_, err = v.Verify(t.Context(), original)
		if err == nil {
			t.Fatal("authoritatively removed same-kid key still verified")
		}
		v.RemoveIssuer(authtest.Issuer)
		_, err = v.Verify(t.Context(), rotated)
		if err == nil {
			t.Fatal("removed issuer remained trusted")
		}
		noError(t, v.AddIssuer(authtest.Issuer, []string{authtest.Audience}, options))
		_, err = v.Verify(t.Context(), rotated)
		noError(t, err)
		mu.Lock()
		down = true
		mu.Unlock()
		clock.Advance(11 * time.Minute)
		eventually(t, "failed asynchronous JWKS refresh", func() bool { return v.CheckIssuerKeys(t.Context()) != nil })
		_, err = v.Verify(t.Context(), rotated)
		noError(t, err)
		clock.Advance(4 * time.Hour)
		_, err = v.Verify(t.Context(), rotated)
		e, ok := iam.AsError(err)
		if !ok || e.Status() != http.StatusServiceUnavailable || e.Code() != "issuer_keys_unavailable" {
			t.Fatalf("past-max-stale key still trusted or misclassified: %v", err)
		}
	})
	t.Run("AK-J13-C05_ID_token_requires_registered_client_and_live_session", func(t *testing.T) {
		u := f.user(t)
		session := f.signIn(t, u)
		raw := fixtureIDToken(t, f, session.AccessToken)
		_, err := f.auth.VerifyIDToken(t.Context(), raw)
		noError(t, err)
		h, c := jwtParts(t, raw)
		c["azp"] = "not-registered"
		c["aud"] = []string{"not-registered"}
		_, err = f.auth.VerifyIDToken(t.Context(), signJWT(t, f.deps.KeySource.ActiveSigner(), h, c))
		if !errors.Is(err, iam.ErrInvalidIDToken) {
			t.Fatalf("unregistered ID-token client accepted: %v", err)
		}
		claims, err := f.auth.Verify(t.Context(), session.AccessToken)
		noError(t, err)
		noError(t, f.auth.RevokeSession(t.Context(), iam.SystemIdentity(), u.ID, claims.SessionID))
		_, err = f.auth.VerifyIDToken(t.Context(), raw)
		if !errors.Is(err, iam.ErrInvalidIDToken) {
			t.Fatalf("ID-token outlived its sign-in: %v", err)
		}
	})
	t.Run("AK-J13-C06_host_mints_cannot_override_reserved_authority", func(t *testing.T) {
		u := f.user(t)
		session := f.signIn(t, u)
		cl, err := f.auth.Verify(t.Context(), session.AccessToken)
		noError(t, err)
		for _, field := range []string{"sub", "sid", "auth_time", "permissions", "tenant_id"} {
			_, err := f.auth.MintAccessToken(t.Context(), u.ID, iam.AccessTokenOptions{SessionID: cl.SessionID, Claims: map[string]any{field: "forged"}})
			e, ok := iam.AsError(err)
			if !ok || e.Code() != "invalid_request" {
				t.Fatalf("reserved claim%s accepted: %v", field, err)
			}
		}
		mint, err := f.auth.MintAccessToken(t.Context(), u.ID, iam.AccessTokenOptions{SessionID: cl.SessionID, Claims: map[string]any{"critical_trace": "known-host-value"}})
		noError(t, err)
		v := verify.NewVerifier()
		defer v.Close()
		noError(t, v.AddIssuer(authtest.Issuer, []string{authtest.Audience}, verify.IssuerOptions{KeySource: f.deps.KeySource}))
		data, err := v.VerifyClaims(t.Context(), mint.Value)
		noError(t, err)
		if data["critical_trace"] != "known-host-value" || data["sub"] != u.ID {
			t.Fatal("host mint lost its independent custom claim or changed identity")
		}
		g, _, _ := f.ownedGroup(t)
		_, err = f.auth.MintAccessToken(t.Context(), u.ID, iam.AccessTokenOptions{Group: iam.GroupByID(g.ID), TTL: 24 * time.Hour})
		if e, ok := iam.AsError(err); !ok || e.Code() != "invalid_request" {
			t.Fatalf("oversized group lifetime accepted: %v", err)
		}
		bound, err := f.auth.MintAccessToken(t.Context(), u.ID, iam.AccessTokenOptions{Group: iam.GroupByID(g.ID), TTL: 15 * time.Minute})
		noError(t, err)
		if bound.ExpiresAt.After(time.Now().Add(15*time.Minute + time.Second)) {
			t.Fatal("group-bound mint exceeded its documented lifetime cap")
		}
		f.call(t, "GET", "/me", bound.Value, nil).want(t, http.StatusForbidden, "forbidden")
	})
}
