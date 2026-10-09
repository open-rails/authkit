package authtest

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"net/http"
	"testing"
	"time"

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

func (k *DPoPKey) coordinates() (string, string) {
	public, _ := k.key.PublicKey.Bytes()
	return base64.RawURLEncoding.EncodeToString(public[1:33]), base64.RawURLEncoding.EncodeToString(public[33:])
}
