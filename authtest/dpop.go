package authtest

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"net/http"
	"net/url"
	"sync"
	"testing"
	"time"

	"github.com/open-rails/authkit"

	jwt "github.com/golang-jwt/jwt/v5"
)

// DPoPKey is a client's RFC 9449 proof-of-possession key (ES256), as a
// browser keeps it: tokens bound to it name its Thumbprint, and every
// request using them carries a fresh Proof.
type DPoPKey struct{ key *ecdsa.PrivateKey }

// NewDPoPKey generates a P-256 key.
func NewDPoPKey(t testing.TB) *DPoPKey {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("authtest: DPoP key: %v", err)
	}
	return &DPoPKey{key: key}
}

// Thumbprint is the key's RFC 7638 thumbprint: a bound token's cnf.jkt.
func (k *DPoPKey) Thumbprint() string {
	x, y := k.coordinates()
	sum := sha256.Sum256([]byte(`{"crv":"P-256","kty":"EC","x":"` + x + `","y":"` + y + `"}`))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

// Proof is a single-use DPoP proof for method and target (no query):
// accessToken is the token it accompanies ("" at a token endpoint), nonce
// the server's DPoP-Nonce ("" for none).
func (k *DPoPKey) Proof(t testing.TB, method, target, accessToken, nonce string) string {
	t.Helper()
	jti := make([]byte, 16)
	_, _ = rand.Read(jti)
	claims := jwt.MapClaims{"htm": method, "htu": target, "iat": time.Now().Unix(), "jti": base64.RawURLEncoding.EncodeToString(jti)}
	if accessToken != "" {
		sum := sha256.Sum256([]byte(accessToken))
		claims["ath"] = base64.RawURLEncoding.EncodeToString(sum[:])
	}
	if nonce != "" {
		claims["nonce"] = nonce
	}
	token := jwt.NewWithClaims(jwt.SigningMethodES256, claims)
	x, y := k.coordinates()
	token.Header["typ"] = "dpop+jwt"
	token.Header["jwk"] = map[string]any{"kty": "EC", "crv": "P-256", "x": x, "y": y}
	proof, err := token.SignedString(k.key)
	if err != nil {
		t.Fatalf("authtest: DPoP proof: %v", err)
	}
	return proof
}

// Authorize sets req's DPoP-bound Authorization and a fresh proof for its
// method and URL (without the query).
func (k *DPoPKey) Authorize(t testing.TB, req *http.Request, accessToken, nonce string) {
	t.Helper()
	target := *req.URL
	target.RawQuery, target.Fragment = "", ""
	req.Header.Set("Authorization", "DPoP "+accessToken)
	req.Header.Set("DPoP", k.Proof(t, req.Method, target.String(), accessToken, nonce))
}

// Assertion is an RFC 7523 JWT-bearer assertion's claims, as a workload
// signs them (DPoPKey.Assertion).
type Assertion struct {
	// Issuer (iss) is the client_id.
	Issuer string
	// Subject (sub) names the workload; "" is the key's Thumbprint.
	Subject string
	// Audience (aud) is the token endpoint (AuthorizationServer.
	// TokenEndpoint).
	Audience string
	// Lifetime sets exp from now: 0 is one minute; a negative one makes an
	// expired assertion.
	Lifetime time.Duration
	// ID (jti) is "" for a random one.
	ID string
	// Capability is the device-key capability it carries
	// (DeviceKey.Capability).
	Capability string
	// Claims are extra claims.
	Claims map[string]any
}

// Assertion signs a with the key, its public JWK in the header, as a
// workload asserts itself for the jwt-bearer grant.
func (k *DPoPKey) Assertion(t testing.TB, a Assertion) string {
	t.Helper()
	now := time.Now()
	lifetime := a.Lifetime
	if lifetime == 0 {
		lifetime = time.Minute
	}
	if a.Subject == "" {
		a.Subject = k.Thumbprint()
	}
	if a.ID == "" {
		jti := make([]byte, 16)
		_, _ = rand.Read(jti)
		a.ID = base64.RawURLEncoding.EncodeToString(jti)
	}
	claims := jwt.MapClaims{}
	for name, value := range a.Claims {
		claims[name] = value
	}
	claims["iss"], claims["sub"], claims["aud"], claims["jti"] = a.Issuer, a.Subject, a.Audience, a.ID
	if a.Capability != "" {
		claims["capability"] = a.Capability
	}
	claims["iat"], claims["exp"] = now.Unix(), now.Add(lifetime).Unix()
	token := jwt.NewWithClaims(jwt.SigningMethodES256, claims)
	x, y := k.coordinates()
	token.Header["typ"] = "JWT"
	token.Header["jwk"] = map[string]any{"kty": "EC", "crv": "P-256", "x": x, "y": y}
	assertion, err := token.SignedString(k.key)
	if err != nil {
		t.Fatalf("authtest: assertion: %v", err)
	}
	return assertion
}

func (k *DPoPKey) coordinates() (string, string) {
	public, _ := k.key.PublicKey.Bytes()
	return base64.RawURLEncoding.EncodeToString(public[1:33]), base64.RawURLEncoding.EncodeToString(public[33:])
}

// boundKeys remembers the DPoP key SignIn bound each session's tokens to.
var boundKeys sync.Map

func bindTokens(key *DPoPKey, tokens ...string) {
	for _, token := range tokens {
		if key != nil && token != "" {
			boundKeys.Store(token, key)
		}
	}
}

func keyFor(token string) *DPoPKey {
	if k, ok := boundKeys.Load(token); ok {
		return k.(*DPoPKey)
	}
	return nil
}

// Authorize sets r's credential as a browser sends it: a token SignIn bound
// to a DPoP key goes as DPoP with a fresh proof naming auth's public origin
// and r's path, as the host's routes behind auth.Authenticator() check it;
// any other token or API key as Bearer.
func Authorize(t testing.TB, auth *authkit.Client, r *http.Request, token string) {
	t.Helper()
	key := keyFor(token)
	if key == nil {
		r.Header.Set("Authorization", "Bearer "+token)
		return
	}
	base, err := url.Parse(auth.PublicAPIBase())
	if err != nil || base.Host == "" {
		t.Fatal("authtest: the Client serves no HTTP (Config.HTTP)")
	}
	r.Header.Set("Authorization", "DPoP "+token)
	r.Header.Set("DPoP", key.Proof(t, r.Method, base.Scheme+"://"+base.Host+r.URL.EscapedPath(), token, ""))
}

// requiresDPoP reports whether auth's sign-ins need a DPoP key, from its
// configuration: asking /capabilities would spend the caller's rate limit.
func requiresDPoP(t testing.TB, auth *authkit.Client) bool {
	t.Helper()
	cfg, _ := builtWith(t, auth)
	return cfg.SignIn.DPoP == authkit.DPoPRequired
}
