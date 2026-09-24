package securitytest

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"maps"
	"net/http"
	"strings"
	"testing"
	"time"

	jwt "github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/require"
)

// splitToken returns a verified-by-issuance token's header and claims so an
// attack can change exactly one property and re-sign.
func splitToken(t *testing.T, token string) (map[string]any, jwt.MapClaims) {
	t.Helper()
	claims := jwt.MapClaims{}
	parsed, _, err := jwt.NewParser().ParseUnverified(token, claims)
	require.NoError(t, err)
	return parsed.Header, claims
}

func sign(t *testing.T, method jwt.SigningMethod, key any, header map[string]any, claims jwt.MapClaims) string {
	t.Helper()
	tok := jwt.NewWithClaims(method, claims)
	for k, v := range header {
		if k != "alg" {
			tok.Header[k] = v
		}
	}
	out, err := tok.SignedString(key)
	require.NoError(t, err)
	return out
}

func unsignedToken(header map[string]any, claims jwt.MapClaims, alg string) string {
	h := maps.Clone(header)
	h["alg"] = alg
	hb, _ := json.Marshal(h)
	cb, _ := json.Marshal(claims)
	enc := base64.RawURLEncoding
	return enc.EncodeToString(hb) + "." + enc.EncodeToString(cb) + "."
}

// TestSecurityAccessTokenForgery presents access tokens that differ from a
// genuine one in exactly one attacker-controlled property. Only the unmodified
// re-signature may authenticate.
func TestSecurityAccessTokenForgery(t *testing.T) {
	h := newHost(t, withHTTP(generousLimits))
	victim := h.newAccount("forgery")
	genuine := h.login(victim).AccessToken
	header, claims := splitToken(t, genuine)
	key := signer().PrivateKey()
	pubDER, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	require.NoError(t, err)
	pubPEM := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubDER})
	otherRSA, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	otherEC, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	now := time.Now()

	with := func(mutate func(jwt.MapClaims)) jwt.MapClaims {
		c := maps.Clone(claims)
		mutate(c)
		return c
	}
	withHeader := func(mutate func(map[string]any)) map[string]any {
		hd := maps.Clone(header)
		mutate(hd)
		return hd
	}
	rs := func(hd map[string]any, c jwt.MapClaims) string { return sign(t, jwt.SigningMethodRS256, key, hd, c) }

	cases := []struct {
		name  string
		token string
		ok    bool
	}{
		{"control: genuine token", genuine, true},
		{"control: unmodified re-signature", rs(header, claims), true},
		{"alg none", unsignedToken(header, claims, "none"), false},
		{"alg None", unsignedToken(header, claims, "None"), false},
		{"HS256 keyed with the RSA public key PEM", sign(t, jwt.SigningMethodHS256, pubPEM, header, claims), false},
		{"HS256 keyed with the RSA public key DER", sign(t, jwt.SigningMethodHS256, pubDER, header, claims), false},
		{"RS256 signed by an attacker key under the real kid", sign(t, jwt.SigningMethodRS256, otherRSA, header, claims), false},
		{"ES256 signed by an attacker key under the real kid", sign(t, jwt.SigningMethodES256, otherEC, header, claims), false},
		{"PS256 with the real key (unlisted algorithm)", sign(t, jwt.SigningMethodPS256, key, header, claims), false},
		{"kid path traversal", rs(withHeader(func(m map[string]any) { m["kid"] = "../../../../dev/null" }), claims), false},
		{"unknown kid", rs(withHeader(func(m map[string]any) { m["kid"] = "attacker-kid" }), claims), false},
		{"jku pointing at attacker JWKS", sign(t, jwt.SigningMethodRS256, otherRSA, withHeader(func(m map[string]any) { m["jku"] = "https://evil.test/jwks.json" }), claims), false},
		{"embedded jwk header", sign(t, jwt.SigningMethodRS256, otherRSA, withHeader(func(m map[string]any) {
			m["jwk"] = map[string]any{"kty": "RSA", "n": base64.RawURLEncoding.EncodeToString(otherRSA.N.Bytes()), "e": "AQAB"}
		}), claims), false},
		{"payload swapped under a genuine signature", func() string {
			parts := strings.Split(genuine, ".")
			forged := with(func(c jwt.MapClaims) { c["sub"] = "00000000-0000-0000-0000-000000000001" })
			cb, _ := json.Marshal(forged)
			return parts[0] + "." + base64.RawURLEncoding.EncodeToString(cb) + "." + parts[2]
		}(), false},
		{"wrong audience", rs(header, with(func(c jwt.MapClaims) { c["aud"] = []string{"other-app"} })), false},
		{"audience missing", rs(header, with(func(c jwt.MapClaims) { delete(c, "aud") })), false},
		{"wrong issuer", rs(header, with(func(c jwt.MapClaims) { c["iss"] = "https://evil.test" })), false},
		{"issuer with trailing slash", rs(header, with(func(c jwt.MapClaims) { c["iss"] = issuer + "/" })), false},
		{"issuer missing", rs(header, with(func(c jwt.MapClaims) { delete(c, "iss") })), false},
		{"expired beyond skew", rs(header, with(func(c jwt.MapClaims) { c["exp"] = now.Add(-10 * time.Minute).Unix() })), false},
		{"exp missing", rs(header, with(func(c jwt.MapClaims) { delete(c, "exp") })), false},
		{"nbf in the future", rs(header, with(func(c jwt.MapClaims) { c["nbf"] = now.Add(10 * time.Minute).Unix() })), false},
		{"iat in the future", rs(header, with(func(c jwt.MapClaims) { c["iat"] = now.Add(10 * time.Minute).Unix() })), false},
		{"subject of a nonexistent user", rs(header, with(func(c jwt.MapClaims) { c["sub"] = "00000000-0000-0000-0000-000000000001" })), false},
		{"subject not a UUID", rs(header, with(func(c jwt.MapClaims) { c["sub"] = "admin" })), false},
		{"refresh-token typ", rs(withHeader(func(m map[string]any) { m["typ"] = "refresh+jwt" }), claims), false},
		{"service typ", rs(withHeader(func(m map[string]any) { m["typ"] = "service+jwt" }), with(func(c jwt.MapClaims) { c["token_use"] = "service" })), false},
		{"truncated signature", genuine[:len(genuine)-4], false},
		{"extra segment", genuine + ".AAAA", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			resp := h.get("/me", tc.token)
			if tc.ok {
				require.Equal(t, http.StatusOK, resp.status, resp.String())
				return
			}
			require.GreaterOrEqual(t, resp.status, 400, resp.String())
			require.NotContains(t, resp.String(), victim.email)
		})
	}
}

// TestSecurityBearerTransport rejects credentials in places a browser or proxy
// could leak or forge them.
func TestSecurityBearerTransport(t *testing.T) {
	h := newHost(t, withHTTP(generousLimits))
	a := h.newAccount("transport")
	access := h.login(a).AccessToken
	for _, tc := range []struct {
		name   string
		header http.Header
		path   string
	}{
		{"query parameter", nil, "/me?access_token=" + access},
		{"basic scheme", http.Header{"Authorization": {"Basic " + access}}, "/me"},
		{"token scheme", http.Header{"Authorization": {"Token " + access}}, "/me"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			resp := h.do(request{method: http.MethodGet, path: tc.path, header: tc.header})
			require.Equal(t, http.StatusUnauthorized, resp.status, resp.String())
		})
	}
}
