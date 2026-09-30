package keys

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"errors"
	"math/big"
	"testing"
)

func TestPublicToJWK_RSA(t *testing.T) {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	jwk := PublicJWK(&key.PublicKey, "k1", "")
	if jwk.Kty != "RSA" || jwk.Alg != "RS256" || jwk.N == "" || jwk.E == "" {
		t.Fatalf("unexpected jwk: %+v", jwk)
	}
}

func TestPublicToJWK_EC(t *testing.T) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	jwk := PublicJWK(&key.PublicKey, "k1", "")
	if jwk.Kty != "EC" || jwk.Crv != "P-256" || jwk.X == "" || jwk.Y == "" {
		t.Fatalf("unexpected jwk: %+v", jwk)
	}
}

func TestPublicToJWK_Ed25519(t *testing.T) {
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	pub := priv.Public().(ed25519.PublicKey)
	jwk := PublicJWK(pub, "k1", "")
	if jwk.Kty != "OKP" || jwk.Crv != "Ed25519" || jwk.X == "" {
		t.Fatalf("unexpected jwk: %+v", jwk)
	}
}

func TestJWKSToPublicKeys_EC_RoundTrip(t *testing.T) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	jwk := PublicJWK(&key.PublicKey, "ec1", "ES256")
	keys, err := PublicKeys(JWKS{Keys: []JWK{jwk}})
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := keys["ec1"].(*ecdsa.PublicKey); !ok {
		t.Fatalf("got %T", keys["ec1"])
	}
}

// A set's unusable keys are skipped; one with none usable is an error.
func TestPublicKeysSkipsUnusableKeys(t *testing.T) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	got, err := PublicKeys(JWKS{Keys: []JWK{{Kty: "oct", Kid: "x"}, {Kty: "RSA", Kid: "bad", N: "AQAB", E: "AQAB"}, PublicJWK(&key.PublicKey, "good", "")}})
	if err != nil || len(got) != 1 || got["good"] == nil {
		t.Fatalf("got %v, %v", got, err)
	}
	if _, err := PublicKeys(JWKS{Keys: []JWK{{Kty: "oct", Kid: "x"}}}); err == nil {
		t.Fatal("a set without a usable key is an error")
	}
	if _, err := publicKey(JWK{Kty: "oct"}); !errors.Is(err, errUnsupportedJWK) {
		t.Fatalf("got %v", err)
	}
}

func TestBase64URLCanonicalLeadingZeros(t *testing.T) {
	e := base64URLEncode(big.NewInt(65537))
	if e != "AQAB" {
		t.Fatalf("e = %q", e)
	}
}

// ak#275 (ae/jwks-key-strength-validation): publicKey is on the live
// verification path — PublicKeys feeds verify.Verifier — and used to
// accept any key the document supplied. These pin the floor.

func TestJWKToPublicKey_RSAStrength(t *testing.T) {
	strong, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	weak, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatal(err)
	}
	huge := &rsa.PublicKey{N: new(big.Int).Lsh(big.NewInt(1), 8193), E: 65537}

	// A JWK carrying an arbitrary exponent, so e can be corrupted independently.
	withE := func(pub *rsa.PublicKey, e int64) JWK {
		j := PublicJWK(pub, "k", "RS256")
		j.E = base64URLEncode(big.NewInt(e))
		return j
	}

	cases := []struct {
		name    string
		jwk     JWK
		wantErr bool
	}{
		{name: "2048 accepted", jwk: PublicJWK(&strong.PublicKey, "k", "RS256")},
		{name: "1024 rejected", jwk: PublicJWK(&weak.PublicKey, "k", "RS256"), wantErr: true},
		{name: "oversized modulus rejected", jwk: PublicJWK(huge, "k", "RS256"), wantErr: true},
		{name: "even exponent rejected", jwk: withE(&strong.PublicKey, 4), wantErr: true},
		{name: "identity exponent rejected", jwk: withE(&strong.PublicKey, 1), wantErr: true},
		{name: "e=65537 accepted", jwk: withE(&strong.PublicKey, 65537)},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := publicKey(tc.jwk)
			if tc.wantErr && err == nil {
				t.Fatal("expected rejection, got nil")
			}
			if !tc.wantErr && err != nil {
				t.Fatalf("expected acceptance, got %v", err)
			}
		})
	}
}

func TestJWKToPublicKey_ECPointOnCurve(t *testing.T) {
	for _, crv := range []elliptic.Curve{elliptic.P256(), elliptic.P384(), elliptic.P521()} {
		priv, err := ecdsa.GenerateKey(crv, rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		name := crv.Params().Name

		t.Run(name+" valid point accepted", func(t *testing.T) {
			if _, err := publicKey(PublicJWK(&priv.PublicKey, "k", "")); err != nil {
				t.Fatalf("expected acceptance, got %v", err)
			}
		})

		t.Run(name+" off-curve point rejected", func(t *testing.T) {
			jwk := PublicJWK(&priv.PublicKey, "k", "")
			y, err := base64.RawURLEncoding.DecodeString(jwk.Y)
			if err != nil {
				t.Fatal(err)
			}
			y[len(y)-1] ^= 0x01
			jwk.Y = base64.RawURLEncoding.EncodeToString(y)
			if _, err := publicKey(jwk); err == nil {
				t.Fatal("expected off-curve point to be rejected")
			}
		})

		t.Run(name+" oversized coordinate rejected", func(t *testing.T) {
			jwk := PublicJWK(&priv.PublicKey, "k", "")
			// Two extra leading bytes puts X past the curve's field size; this must
			// be an error, never a panic.
			x, err := base64.RawURLEncoding.DecodeString(jwk.X)
			if err != nil {
				t.Fatal(err)
			}
			jwk.X = base64.RawURLEncoding.EncodeToString(append([]byte{0xff, 0xff}, x...))
			if _, err := publicKey(jwk); err == nil {
				t.Fatal("expected oversized coordinate to be rejected")
			}
		})

		t.Run(name+" identity point rejected", func(t *testing.T) {
			jwk := PublicJWK(&priv.PublicKey, "k", "")
			size := len(mustDecodeB64(t, jwk.X))
			zero := base64.RawURLEncoding.EncodeToString(make([]byte, size))
			jwk.X, jwk.Y = zero, zero
			if _, err := publicKey(jwk); err == nil {
				t.Fatal("expected the identity point to be rejected")
			}
		})
	}
}

func mustDecodeB64(t *testing.T, s string) []byte {
	t.Helper()
	b, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}
