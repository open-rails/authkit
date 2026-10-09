package authflow_test

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"testing"
	"time"

	jwt "github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/stretchr/testify/require"

	"github.com/open-rails/authkit/devicekey"
	"github.com/open-rails/authkit/internal/authflow"
	"github.com/open-rails/authkit/internal/testdpop"
)

const (
	assertionClient   = "tensord"
	assertionEndpoint = "https://auth.example.com/oauth2/token"
	capabilityAud     = "https://hub.example.com"
)

func signAssertion(t *testing.T, key *ecdsa.PrivateKey, change func(*jwt.Token)) string {
	t.Helper()
	now := time.Now()
	token := jwt.NewWithClaims(jwt.SigningMethodES256, jwt.MapClaims{
		"iss": assertionClient, "sub": "worker-1", "aud": assertionEndpoint, "capability": "a.b.c",
		"iat": now.Unix(), "exp": now.Add(time.Minute).Unix(), "jti": "0123456789abcdef",
	})
	public, err := key.PublicKey.Bytes()
	require.NoError(t, err)
	b64 := base64.RawURLEncoding.EncodeToString
	token.Header["typ"] = "JWT"
	token.Header["jwk"] = map[string]any{"kty": "EC", "crv": "P-256", "x": b64(public[1:33]), "y": b64(public[33:])}
	if change != nil {
		change(token)
	}
	signed, err := token.SignedString(key)
	require.NoError(t, err)
	return signed
}

func claim(name string, value any) func(*jwt.Token) {
	return func(t *jwt.Token) { t.Claims.(jwt.MapClaims)[name] = value }
}

func header(name string, value any) func(*jwt.Token) {
	return func(t *jwt.Token) { t.Header[name] = value }
}

func unset(name string) func(*jwt.Token) {
	return func(t *jwt.Token) { delete(t.Claims.(jwt.MapClaims), name) }
}

// TestParseJWTBearerAssertion pins what an assertion must be; the grant's
// integration tests cover the token endpoint end to end.
func TestParseJWTBearerAssertion(t *testing.T) {
	key := testdpop.Key(t)
	now := time.Now()
	a, oerr := authflow.ParseJWTBearerAssertion(signAssertion(t, key, func(t *jwt.Token) {
		t.Claims.(jwt.MapClaims)["https://hub.example.com/note"] = map[string]any{"x": 1}
		t.Claims.(jwt.MapClaims)["aud"] = []string{assertionEndpoint}
		delete(t.Header, "typ")
	}), assertionClient, assertionEndpoint, now)
	require.Nil(t, oerr)
	require.Equal(t, testdpop.Thumbprint(t, key), a.JKT)
	require.Equal(t, "worker-1", a.Subject)
	require.Equal(t, "0123456789abcdef", a.ID)
	require.Equal(t, "a.b.c", a.Capability)
	require.Equal(t, now.Unix(), a.IssuedAt.Unix())
	require.Equal(t, now.Add(time.Minute).Unix(), a.ExpiresAt.Unix())
	require.Equal(t, map[string]json.RawMessage{"https://hub.example.com/note": json.RawMessage(`{"x":1}`)}, a.Claims)

	for name, change := range map[string]func(*jwt.Token){
		"a kid":                 header("kid", "k1"),
		"crit":                  header("crit", []string{"exp"}),
		"typ dpop+jwt":          header("typ", "dpop+jwt"),
		"a private key":         func(t *jwt.Token) { t.Header["jwk"].(map[string]any)["d"] = "private" },
		"a P-384 key":           func(t *jwt.Token) { t.Header["jwk"].(map[string]any)["crv"] = "P-384" },
		"no key":                func(t *jwt.Token) { delete(t.Header, "jwk") },
		"no iss":                unset("iss"),
		"no sub":                unset("sub"),
		"a sub with spaces":     claim("sub", "worker 1"),
		"two audiences":         claim("aud", []string{assertionEndpoint, "https://other.example"}),
		"an audience prefix":    claim("aud", "https://auth.example.com"),
		"no capability":         unset("capability"),
		"a capability object":   claim("capability", map[string]any{"jws": "a.b.c"}),
		"no exp":                unset("exp"),
		"a string exp":          claim("exp", "soon"),
		"a fractional exp":      claim("exp", float64(now.Unix())+60.5),
		"expired past the skew": claim("exp", now.Add(-time.Minute).Unix()),
		"exp too far ahead":     claim("exp", now.Add(6*time.Minute).Unix()),
		"iat in the future":     claim("iat", now.Add(time.Minute).Unix()),
		"nbf in the future":     claim("nbf", now.Add(time.Minute).Unix()),
		"no jti":                unset("jti"),
		"a 15-character jti":    claim("jti", "0123456789abcde"),
	} {
		_, oerr := authflow.ParseJWTBearerAssertion(signAssertion(t, key, change), assertionClient, assertionEndpoint, now)
		require.NotNil(t, oerr, name)
		require.Equal(t, authflow.OAuthInvalidGrant, oerr.Code, name)
		require.Equal(t, authflow.ReasonAssertionInvalid, oerr.Reason, name)
	}
	tampered := signAssertion(t, key, nil)
	other := signAssertion(t, testdpop.Key(t), nil)
	_, oerr = authflow.ParseJWTBearerAssertion(tampered[:len(tampered)-86]+other[len(other)-86:], assertionClient, assertionEndpoint, now)
	require.Equal(t, authflow.ReasonAssertionInvalid, oerr.Reason, "a signature by another key")
	_, oerr = authflow.ParseJWTBearerAssertion(signAssertion(t, key, nil), assertionClient, "", now)
	require.Equal(t, authflow.ReasonAssertionInvalid, oerr.Reason, "no token endpoint to match")
	_, oerr = authflow.ParseJWTBearerAssertion("", assertionClient, assertionEndpoint, now)
	require.Equal(t, authflow.OAuthInvalidRequest, oerr.Code)
	_, oerr = authflow.ParseJWTBearerAssertion(signAssertion(t, key, claim("exp", now.Add(-20*time.Second).Unix())), assertionClient, assertionEndpoint, now)
	require.Nil(t, oerr, "within the skew")
}

// TestVerifyCapability pins what a device key's capability must be.
func TestVerifyCapability(t *testing.T) {
	public, private, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	kid, user := uuid.NewString(), uuid.NewString()
	now := time.Now()
	jkt := testdpop.Thumbprint(t, testdpop.Key(t))
	base := devicekey.Capability{
		UserID: user, Audience: capabilityAud, WorkloadThumbprint: jkt, ID: "run-1-capability-0001",
		AuthorizationDetails: json.RawMessage(`[{"type":"op","action":"read"}]`), ExpiresAt: now.Add(time.Hour),
		Claims: map[string]any{"run": "run-1"},
	}
	sign := func(c devicekey.Capability) string {
		raw, err := devicekey.SignCapability(private, kid, c)
		require.NoError(t, err)
		return raw
	}
	raw := sign(base)
	got, oerr := authflow.CapabilityKeyID(raw)
	require.Nil(t, oerr)
	require.Equal(t, kid, got)
	c, oerr := authflow.VerifyCapability(raw, kid, public, now)
	require.Nil(t, oerr)
	require.Equal(t, user, c.UserID)
	require.Equal(t, kid, c.DeviceKeyID)
	require.Equal(t, capabilityAud, c.Audience)
	require.Equal(t, jkt, c.JKT)
	require.Equal(t, "run-1-capability-0001", c.ID)
	require.JSONEq(t, `[{"type":"op","action":"read"}]`, string(c.AuthorizationDetails))
	require.Equal(t, now.Add(time.Hour).Unix(), c.ExpiresAt.Unix())
	require.Equal(t, map[string]json.RawMessage{"run": json.RawMessage(`"run-1"`)}, c.Claims)

	// Hand-made capabilities, signed by the device key.
	forge := func(headers map[string]any, change func(jwt.MapClaims)) string {
		claims := jwt.MapClaims{
			"sub": user, "aud": capabilityAud, "cnf": map[string]any{"jkt": jkt}, "jti": "run-1-capability-0002",
			"exp": now.Add(time.Hour).Unix(), "authorization_details": []any{map[string]any{"type": "op"}},
		}
		if change != nil {
			change(claims)
		}
		token := jwt.NewWithClaims(jwt.SigningMethodEdDSA, claims)
		token.Header["typ"], token.Header["kid"] = devicekey.CapabilityType, kid
		for name, value := range headers {
			if value == nil {
				delete(token.Header, name)
			} else {
				token.Header[name] = value
			}
		}
		signed, err := token.SignedString(private)
		require.NoError(t, err)
		return signed
	}
	_, oerr = authflow.VerifyCapability(forge(nil, nil), kid, public, now)
	require.Nil(t, oerr)
	for name, raw := range map[string]string{
		"typ JWT":              forge(map[string]any{"typ": "JWT"}, nil),
		"no typ":               forge(map[string]any{"typ": nil}, nil),
		"another kid":          forge(map[string]any{"kid": uuid.NewString()}, nil),
		"a jwk":                forge(map[string]any{"jwk": map[string]any{"kty": "OKP"}}, nil),
		"sub not a user id":    forge(nil, func(c jwt.MapClaims) { c["sub"] = "alice" }),
		"two audiences":        forge(nil, func(c jwt.MapClaims) { c["aud"] = []string{capabilityAud, "https://other.example"} }),
		"no aud":               forge(nil, func(c jwt.MapClaims) { delete(c, "aud") }),
		"no cnf":               forge(nil, func(c jwt.MapClaims) { delete(c, "cnf") }),
		"cnf with more":        forge(nil, func(c jwt.MapClaims) { c["cnf"] = map[string]any{"jkt": jkt, "x5t#S256": "x"} }),
		"cnf not a thumbprint": forge(nil, func(c jwt.MapClaims) { c["cnf"] = map[string]any{"jkt": "short"} }),
		"no jti":               forge(nil, func(c jwt.MapClaims) { delete(c, "jti") }),
		"no operations":        forge(nil, func(c jwt.MapClaims) { delete(c, "authorization_details") }),
		"longer than a day":    forge(nil, func(c jwt.MapClaims) { c["exp"] = now.Add(25 * time.Hour).Unix() }),
		"no exp":               forge(nil, func(c jwt.MapClaims) { delete(c, "exp") }),
		"iat in the future":    forge(nil, func(c jwt.MapClaims) { c["iat"] = now.Add(time.Hour).Unix() }),
		"another key's signature": func() string {
			_, k, _ := ed25519.GenerateKey(rand.Reader)
			r, _ := devicekey.SignCapability(k, kid, base)
			return r
		}(),
	} {
		_, oerr := authflow.VerifyCapability(raw, kid, public, now)
		require.NotNil(t, oerr, name)
		require.Equal(t, authflow.OAuthInvalidGrant, oerr.Code, name)
		require.Equal(t, authflow.ReasonCapabilityInvalid, oerr.Reason, name)
	}
	expired := base
	expired.ExpiresAt = now.Add(-time.Minute)
	_, oerr = authflow.VerifyCapability(sign(expired), kid, public, now)
	require.Equal(t, authflow.ReasonCapabilityExpired, oerr.Reason)
	for _, bad := range []string{"", "a.b.c", forge(map[string]any{"kid": "not-a-uuid"}, nil)} {
		_, oerr = authflow.CapabilityKeyID(bad)
		require.Equal(t, authflow.ReasonCapabilityInvalid, oerr.Reason, bad)
	}
}

func TestNarrowsAuthorizationDetails(t *testing.T) {
	granted := json.RawMessage(`[{"type":"op","action":"read","resource":{"a":1,"b":2}},{"type":"op","action":"publish"}]`)
	for narrowed, want := range map[string]bool{
		`[{"type":"op","action":"publish"}]`:                                  true,
		`[{"resource":{"b":2,"a":1},"action":"read","type":"op"}]`:            true,
		`[{"type":"op","action":"publish"},{"type":"op","action":"publish"}]`: true,
		`[{"type":"op","action":"read"}]`:                                     false,
		`[{"type":"op","action":"delete"}]`:                                   false,
		`[{"type":"op","action":"read","resource":{"a":1.0,"b":2}}]`:          false,
		`{}`: false,
	} {
		require.Equal(t, want, authflow.NarrowsAuthorizationDetails(granted, json.RawMessage(narrowed)), narrowed)
	}
}
