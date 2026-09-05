package authhttp

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"github.com/open-rails/authkit/verify"
	"testing"
	"time"

	jwt "github.com/golang-jwt/jwt/v5"
	authkittesting "github.com/open-rails/authkit/authtest"
	"github.com/open-rails/authkit/jwtkit"
)

func TestVerifierAcceptsES256RemoteApplicationIssuer(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := jwtkit.NewSignerFromPEM("ec-kid", mustMarshalECPrivatePEM(t, key))
	if err != nil {
		t.Fatal(err)
	}
	issuer := authkittesting.NewTestIssuerWithSigner(signer, "openrails")
	defer issuer.Close()

	v := verify.NewVerifier(verify.WithSkew(5 * time.Second))
	if err := v.AddIssuer(issuer.URL(), []string{issuer.Audience()}, verify.IssuerOptions{
		JWKSURI: issuer.URL() + "/.well-known/jwks.json",
	}); err != nil {
		t.Fatal(err)
	}

	token, err := signer.Sign(context.Background(), jwt.MapClaims{
		"sub": "actor-1",
		"iss": issuer.URL(),
		"aud": issuer.Audience(),
		"exp": time.Now().Add(time.Hour).Unix(),
		"iat": time.Now().Unix(),
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := v.VerifyClaims(token); err != nil {
		t.Fatalf("verify ES256: %v", err)
	}
}

func TestVerifierAcceptsEdDSARemoteApplicationIssuer(t *testing.T) {
	signer, err := jwtkit.NewEd25519Signer("ed-kid")
	if err != nil {
		t.Fatal(err)
	}
	issuer := authkittesting.NewTestIssuerWithSigner(signer, "openrails")
	defer issuer.Close()

	v := verify.NewVerifier(verify.WithSkew(5 * time.Second))
	if err := v.AddIssuer(issuer.URL(), []string{issuer.Audience()}, verify.IssuerOptions{
		JWKSURI: issuer.URL() + "/.well-known/jwks.json",
	}); err != nil {
		t.Fatal(err)
	}

	token := issuer.CreateToken("actor-2", "a@b.com")
	if _, err := v.VerifyClaims(token); err != nil {
		t.Fatalf("verify EdDSA: %v", err)
	}
}

// TestVerifierRejectsHS256 pins the algorithm-confusion attack: an HS256 token
// must be refused at key resolution (disallowed_alg) whatever the secret, and in
// particular when the secret is the issuer's own public key bytes — the classic
// RSA-public-key-as-HMAC-secret confusion. alg=none stays its own case.
func TestVerifierRejectsHS256(t *testing.T) {
	signer, err := jwtkit.NewRSASigner(2048, "k")
	if err != nil {
		t.Fatal(err)
	}
	v := verify.NewVerifier()
	if err := v.AddIssuer("https://issuer.example", nil, verify.IssuerOptions{RawKeys: map[string]crypto.PublicKey{
		signer.KID(): signer.PublicKey(),
	}}); err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKIXPublicKey(signer.PublicKey())
	if err != nil {
		t.Fatal(err)
	}
	publicPEM := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})
	claims := jwt.MapClaims{"iss": "https://issuer.example", "sub": "x", "exp": time.Now().Add(time.Hour).Unix()}

	// Control: the same claims signed RS256 by the issuer verify, so the HS256
	// rejections below are about the algorithm, not the claims or the kid.
	control, err := signer.Sign(context.Background(), claims)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := v.VerifyClaims(control); err != nil {
		t.Fatalf("RS256 control token must verify: %v", err)
	}

	for name, secret := range map[string][]byte{"arbitrary secret": []byte("any"), "issuer public key as secret": publicPEM} {
		token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
		token.Header["kid"] = signer.KID()
		signed, err := token.SignedString(secret)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := v.VerifyClaims(signed); err == nil {
			t.Fatalf("HS256 with %s must be rejected", name)
		}
	}

	token := jwt.NewWithClaims(jwt.SigningMethodNone, claims)
	unsigned, err := token.SignedString(jwt.UnsafeAllowNoneSignatureType)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := v.VerifyClaims(unsigned); err == nil {
		t.Fatal("expected rejection for none alg")
	}
}

func mustMarshalECPrivatePEM(t *testing.T, key *ecdsa.PrivateKey) []byte {
	t.Helper()
	der, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der})
}
